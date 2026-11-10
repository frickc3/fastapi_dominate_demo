"""
FastSite application entry point.

Run with:   python -m fastsite.main     (from the ``fastsite`` folder)
URL:        http://127.0.0.1:8112/

Security posture
----------------
* Sessions — starlette SessionMiddleware signed cookies (itsdangerous,
  URLSafeTimedSerializer); HttpOnly, SameSite=Strict, Max-Age 3600 s, secret
  auto-generated in ``data/session_key.txt`` (``FASTSITE_SECRET`` overrides).
* CSRF — hidden per-session token required on every POST + Origin/Referer
  check; logout is POST-only (dependency ``protected_form``).
* Rate limiting — 5 failed logins per IP per 10 minutes → HTTP 429.
* Passwords — scrypt (see db.py), constant-time verification.
* Storage — fastlite dataclass tables over a SQLCipher (AES-256) file.
* Headers — strict CSP, nosniff, frame denial on every response.
* Request cap — POST bodies over 64 KB are rejected (HTTP 413).
"""

import secrets
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi_security_headers import SecurityHeadersMiddleware, Presets
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import FormData

from . import db, security, views
from .config import get_settings
settings = get_settings()

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
#SESSION_KEY_FILE = DATA_DIR / "session_key.txt"
#PORT = 8000
MAX_BODY = 64 * 1024


"""
def _load_or_create_secret() -> str:
    import os
    env = os.environ.get("FASTSITE_SECRET")
    if env:
        return env
    DATA_DIR.mkdir(exist_ok=True)
    if not SESSION_KEY_FILE.exists():
        SESSION_KEY_FILE.write_text(secrets.token_hex(32), encoding="utf-8")
    secret = SESSION_KEY_FILE.read_text(encoding="utf-8").strip()
    if not secret:
        raise RuntimeError(
            f"Empty session secret file {SESSION_KEY_FILE}; delete it to regenerate."
        )
    return secret
"""

"""
app = FastAPI(title="FastSite", docs_url=None, redoc_url=None,
              openapi_url=None)  # no docs/JSON endpoints in a secure app
"""
app = FastAPI(title="FastSite")

app.add_middleware(
    SecurityHeadersMiddleware,
    config=Presets.swagger_friendly()
)

app.add_middleware(
    SessionMiddleware,
    #secret_key=_load_or_create_secret(),
    secret_key=settings.SESSION_KEY,
    session_cookie="fastsite_session",
    #max_age=3600,            # 1 h
    max_age=settings.SESSION_AGE,
    same_site="strict",
)

# ------------------------------------------------------------ dependencies --

def current_user(request: Request):
    return db.get_user_by_id(request.session.get("user_id"))


async def protected_form(request: Request) -> FormData:
    """Parse the form once (starlette caches it) and validate origin + CSRF.

    Raises HTTP 403 on any mismatch. Use as ``form = Depends(protected_form)``
    in every POST handler.
    """
    try:
        length = int(request.headers.get("content-length") or 0)
    except ValueError:
        length = 0
    if length > MAX_BODY:
        raise HTTPException(status_code=413, detail="Request body too large")
    form = await request.form()
    if not security.origin_ok(request):
        raise HTTPException(status_code=403, detail="Cross-origin state change blocked")
    if not security.csrf_ok(form, request):
        raise HTTPException(status_code=403, detail="Missing or invalid CSRF token")
    return form


def safe_next(target: str) -> str:
    """Only app-relative redirect targets (no open redirect)."""
    from urllib.parse import unquote
    target = unquote(target or "/")
    if target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return "/"


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    security.apply_security_headers(response)
    return response


# ------------------------------------------------------------------ routes --

def html(body: str) -> HTMLResponse:
    return HTMLResponse(content=body, status_code=200)

@app.get("/health")
async def health(request: Request):
    pass

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    user = current_user(request)
    return html(views.index_page(user, security.ensure_csrf_token(request),
                                 flashes=security.pop_flashes(request)))


@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    if current_user(request):
        return RedirectResponse("/notes", status_code=303)
    return html(views.register_form(security.ensure_csrf_token(request)))


@app.post("/register")
async def register_submit(request: Request, form: FormData = Depends(protected_form)):
    email = (form.get("email") or "").strip()
    #username = (form.get("username") or "").strip()
    password = form.get("password") or ""
    password_again = form.get("password_again") or ""

    #error = db.validate_registration(email, username, password, password_again)
    error = db.validate_registration(email, password, password_again)
    if error is None and db.email_in_use(email):
        error = "An account with this email already exists."

    if error:
        return html(views.register_form(
            security.ensure_csrf_token(request), error=error,
            values={"email": email}))     #, "username": username}))

    user = db.register_user(email, password)   # ,username

    # session-fixation defence: drop the old session, then log the user in
    request.session.clear()
    request.session["user_id"] = user.id
    security.ensure_csrf_token(request)
    security.flash(request, "Welcome! Your account is ready.", "success")
    return RedirectResponse("/notes", status_code=303)


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if current_user(request):
        return RedirectResponse("/notes", status_code=303)
    next_url = request.query_params.get("next", "")
    return html(views.login_form(security.ensure_csrf_token(request),
                                 next_url=next_url))


@app.post("/login")
async def login_submit(request: Request, form: FormData = Depends(protected_form)):
    email = (form.get("email") or "").strip()
    password = form.get("password") or ""
    next_url = safe_next(form.get("next", ""))

    ip = request.client.host if request.client else "unknown"
    retry = security.login_limiter.too_many_fails(ip)
    if retry:
        return Response("Too many failed logins. Try again later.",
                        status_code=429,
                        headers={"Retry-After": str(retry),
                                 "Content-Type": "text/plain; charset=utf-8"})

    user = db.authenticate(email, password)
    if user is None:
        security.login_limiter.record_fail(ip)
        return html(views.login_form(
            security.ensure_csrf_token(request),
            error="Invalid email or password.", next_url=next_url))

    security.login_limiter.reset(ip)
    request.session.clear()
    request.session["user_id"] = user.id
    security.ensure_csrf_token(request)
    security.flash(request, f"Welcome back, {user.email}.", "success")
    return RedirectResponse(next_url, status_code=303)


@app.post("/logout")
async def logout(request: Request, form: FormData = Depends(protected_form)):
    request.session.clear()
    security.flash(request, "You have been logged out.", "info")
    return RedirectResponse("/", status_code=303)


@app.get("/notes", response_class=HTMLResponse)
async def notes_page(request: Request):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login?next=%2Fnotes", status_code=303)
    return html(views.notes_page(
        user, db.notes_for(user.id), security.ensure_csrf_token(request),
        flashes=security.pop_flashes(request)))


@app.post("/notes")
async def notes_submit(request: Request, form: FormData = Depends(protected_form)):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login?next=%2Fnotes", status_code=303)
    body = (form.get("body") or "").strip()
    if not body:
        security.flash(request, "Note is empty — nothing saved.", "warning")
        return RedirectResponse("/notes", status_code=303)
    db.add_note(user.id, body[:2000])
    security.flash(request, "Note saved (encrypted at rest).", "success")
    return RedirectResponse("/notes", status_code=303)


@app.post("/notes/delete")
async def notes_delete(request: Request, form: FormData = Depends(protected_form)):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login?next=%2Fnotes", status_code=303)
    deleted = db.delete_note(user.id, form.get("note_id", ""))
    security.flash(request, "Note deleted." if deleted else "Note not found.",
                   "success" if deleted else "warning")
    return RedirectResponse("/notes", status_code=303)


# ------------------------------------------------------------- error pages --

@app.exception_handler(404)
async def not_found(request: Request, exc):
    return HTMLResponse(views.not_found_page(request.url.path), status_code=404)


@app.exception_handler(403)
async def forbidden(request: Request, exc):
    return HTMLResponse(
        views.page("Forbidden · FastSite", t_div_forbidden(str(exc.detail)),
                   user=current_user(request)),
        status_code=403)


def t_div_forbidden(detail: str) -> str:
    from dominate import tags as t
    with t.div(cls="py-24 text-center") as out:
        t.h1("403", cls="text-6xl font-bold mb-4")
        t.p(detail, cls="text-gray-500 mb-6")
        out.add(t.a("Back home", href="/",
                    cls="px-5 py-2.5 rounded-xl bg-white border hover:bg-gray-50"))
    return page_wrap(out)


def page_wrap(content: str) -> str:
    return views.page("Forbidden · FastSite", content, user=None)


def main() -> None:
    import uvicorn
    print(f"[fastsite] SQLCipher db: {db.DB_PATH} ({db.count_users()} user(s))")
    uvicorn.run("main:app", host=settings.HTTP_HOST, port=settings.HTTP_PORT, reload=True, log_level="info")


if __name__ == "__main__":
    main()
