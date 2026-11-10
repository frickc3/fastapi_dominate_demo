"""
Security helpers for FastSite.

* CSRF — a per-session random token embedded as a hidden field in every POST
  form and verified server-side with a constant-time compare (FastAPI has no
  built-in CSRF, SessionMiddleware provides the signed-cookie session).
* Origin checking — every mutating request must carry an Origin or Referer
  header matching the site host (browsers always send one on POSTs).
* Login rate limiting — in-memory sliding window per client IP:
  5 failed logins / 10 minutes → HTTP 429 with Retry-After.
* Security headers — strict CSP (UnoCSS runtime needs inline <style>), nosniff,
  frame denial, applied to every response.
"""

import secrets
import threading
import time
from collections import deque

MAX_FAILS = 5
WINDOW_SECONDS = 10 * 60  # 10 minutes


# ------------------------------------------------------------------- CSRF ---

def ensure_csrf_token(request) -> str:
    """Return the session's CSRF token, creating one when missing (lazily)."""
    token = request.session.get("_csrf")
    if not token:
        token = secrets.token_hex(32)
        request.session["_csrf"] = token
    return token


def csrf_ok(form, request) -> bool:
    """Validate the hidden ``_csrf`` field against the session token."""
    supplied = form.get("_csrf", "")
    stored = request.session.get("_csrf")
    if not supplied or not stored:
        return False
    return secrets.compare_digest(str(supplied), str(stored))


# ---------------------------------------------------------------- origin ----

def origin_ok(request) -> bool:
    """POST requests must originate from this site (Origin/Referer host check)."""
    host = (request.headers.get("host") or "").lower().split(":")[0]
    for header in ("Origin", "Referer"):
        value = request.headers.get(header, " ")
        value = value.strip()
        if value:
            host_from_header = value.lower().split("//", 1)[-1].split("/")[0]
            return host_from_header.split(":")[0] == host
    # A browser-facing form POST without Origin and without Referer is
    # suspicious (browsers send at least one on POSTs).
    return False


# ---------------------------------------------------------- rate limiting ---

class LoginRateLimiter:
    """Sliding-window failed-login limiter, keyed by client IP."""

    def __init__(self, max_fails: int = MAX_FAILS, window: int = WINDOW_SECONDS):
        self.max_fails = max_fails
        self.window = window
        self._fails: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def _prune(self, key: str, now: float) -> None:
        dq = self._fails.get(key)
        if dq is not None:
            while dq and now - dq[0] > self.window:
                dq.popleft()
            if not dq:
                self._fails.pop(key, None)

    def too_many_fails(self, key: str) -> int:
        """Seconds until the client may retry, or 0 when allowed."""
        now = time.monotonic()
        with self._lock:
            self._prune(key, now)
            dq = self._fails.get(key)
            if dq and len(dq) >= self.max_fails:
                return max(int(self.window - (now - dq[0])) + 1, 1)
        return 0

    def record_fail(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            self._prune(key, now)
            self._fails.setdefault(key, deque()).append(now)

    def reset(self, key: str) -> None:
        with self._lock:
            self._fails.pop(key, None)


login_limiter = LoginRateLimiter()


# ------------------------------------------------------------ flash msgs ----

def flash(request, message: str, category: str = "info") -> None:
    request.session.setdefault("_flash", []).append([category, message])


def pop_flashes(request) -> list[tuple[str, str]]:
    return request.session.pop("_flash", [])


# -------------------------------------------------------- security headers --

CSP = (
    "default-src 'self'; "
    "script-src 'self' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "img-src 'self' data:; "
    "font-src https://cdn.jsdelivr.net; "
    "form-action 'self'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "frame-ancestors 'none'"
)

HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
}


def apply_security_headers(response) -> None:
    for name, value in HEADERS.items():
        response.headers[name] = value
