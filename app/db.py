"""
Database layer: fastlite (dataclass tables) running on a **SQLCipher** backend.

fastlite normally opens files with ``apsw.Connection``, which is linked against
plain SQLite and therefore cannot read an encrypted database. This module
instead hands fastlite a ``sqlcipher3`` connection wrapped in a tiny adapter
that provides the one apsw-specific hook ``apswutils.db.Database.__init__``
uses: ``conn.pragma(name, *params)``.

Ordering matters: ``PRAGMA key`` MUST be the first statement executed on a
SQLCipher connection, so the key is applied before anything else.
"""

import hmac
import re
import secrets
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from dataclasses import dataclass
from datetime import datetime
from email_validator import validate_email, EmailNotValidError
#from hashlib import scrypt
from icecream import ic
from password_validation import PasswordPolicy
from pathlib import Path

import sqlcipher3.dbapi2 as sqlcipher_driver
from fastlite import Database
from .config import get_settings
settings = get_settings()

# ---------------------------------------------------------------- layout ----

BASE_DIR = Path(__file__).resolve().parent.parent  # .../fastsite/
#DATA_DIR = BASE_DIR / "data"
DB_DIR = settings.DB_PATH
#DB_PATH = DATA_DIR / "vault.db"
DB_NAME = settings.DB_NAME
#KEY_FILE = BASE_DIR / "private" / "db_key.txt"

ph = PasswordHasher(
    time_cost=2,
    memory_cost=19456,      # 19 MiB
    parallelism=1
)

pwd_policy = PasswordPolicy(
    uppercase=1,
    symbols=1,
    numbers=1,
    min_length=12,
    max_length=60,
)


def _load_or_create_key() -> str:
    """SQLCipher key: ``FASTSQLCIPHER_KEY`` env var, else ``private/db_key.txt``.

    Losing the key file means losing the database — back it up.
    """
    import os

    env = os.environ.get("FASTSQLCIPHER_KEY")
    if env:
        return env
    KEY_FILE.parent.mkdir(exist_ok=True)
    if not KEY_FILE.exists():
        KEY_FILE.write_text(secrets.token_hex(32), encoding="utf-8")
    key = KEY_FILE.read_text(encoding="utf-8").strip()
    if not key:
        raise RuntimeError(f"Empty key file {KEY_FILE}; delete it to regenerate.")
    return key


# ------------------------------------------------- apsw-style conn adapter ---

class SqlCipherCursor:
    """Wraps a sqlite3.Cursor to satisfy the two apsw-specific cursor hooks
    apswutils relies on: settable attributes (``row_trace``) and
    ``get_description()`` (apsw returns ``(name, sqlite_type)`` pairs)."""

    def __init__(self, cursor):
        self._cursor = cursor
        self.row_trace = None

    def get_description(self):
        return [(d[0], d[1]) for d in self._cursor.description]

    def _trace(self, row):
        if self.row_trace is not None:
            return self.row_trace(self, row)
        return row

    def __iter__(self):
        for row in self._cursor.__iter__():
            yield self._trace(row)

    def __next__(self):
        return self._trace(self._cursor.__next__())

    def __getattr__(self, name):  # fetchone/fetchall/lastrowid/...
        return getattr(self._cursor, name)


class SqlCipherConn:
    """Thin adapter so ``apswutils.db.Database`` can drive a sqlcipher3 conn.

    sqlcipher3.Connection is a PEP-249 sqlite3.Connection, so ``execute``,
    ``commit``, ``cursor``, ``close`` etc. all exist; only apsw's dynamic
    ``pragma(...)`` hook, settable cursor attributes and
    ``cursor.get_description()`` are re-implemented here.
    """

    def __init__(self, conn):
        self._conn = conn

    def pragma(self, name, *params):
        if params:
            value = params[0]
            if isinstance(value, bool):
                value = int(value)
            elif isinstance(value, str):
                value = "'" + value.replace("'", "''") + "'"
            self._conn.execute(f"pragma {name} = {value}")
        return self._conn.execute(f"pragma {name}").fetchall()

    def execute(self, sql, parameters=None):
        if parameters:
            cursor = self._conn.execute(sql, tuple(parameters))
        else:
            cursor = self._conn.execute(sql)
        return SqlCipherCursor(cursor)

    def __getattr__(self, name):  # commit/close/cursor/rollassthrough...
        return getattr(self._conn, name)


def open_sqlcipher_database(path: Path, name: str, key: str) -> Database:
    """Open (or create) an encrypted database and return a fastlite Database."""
    path = Path(path)
    path.parent.mkdir(exist_ok=True)
    first_open = not path.exists()

    db_name = f"{path}\\{name}"
    #conn = sqlcipher_driver.connect(str(path), isolation_level=None)    # autocommit
    conn = sqlcipher_driver.connect(db_name, isolation_level=None)
    # PRAGMA key must be the FIRST statement on the connection.
    conn.execute("pragma key = '%s'" % key.replace("'", "''"))
    # Probe: decrypting page 1 fails loudly when the key is wrong.
    try:
        conn.execute("select count(*) from sqlite_master")
    except Exception as exc:
        conn.close()
        raise RuntimeError(
            "SQLCipher: cannot decrypt vault.db with the configured key "
            "(wrong key, foreign file, or corruption): %s" % exc
        ) from exc
    conn.execute("pragma journal_mode=wal")
    return Database(SqlCipherConn(conn))


#db = open_sqlcipher_database(DB_PATH, _load_or_create_key())
db = open_sqlcipher_database(DB_DIR, DB_NAME, settings.DB_SECRET)

# --------------------------------------------------------------- tables ----

@dataclass
class User:
    id: int
    email: str
    #username: str
    password_hash: str
    created_at: str


@dataclass
class Note:
    id: int
    user_id: int
    body: str
    created_at: str


users = db.create(User, pk="id", if_not_exists=True)
notes = db.create(Note, pk="id", if_not_exists=True)


# --------------------------------------------------- password hashing ------

SCRYPT_N = 2 ** 14  # CPU/memory cost (16 MiB per hash)
SCRYPT_R = 8        # block size
SCRYPT_P = 1        # parallelization

"""
def hash_password(password: str) -> str:
    #Self-describing scrypt hash: scrypt$N$r$p$<salt hex>$<key hex>.#
    salt = secrets.token_bytes(16)
    key = scrypt(password.encode("utf-8"), salt=salt,
                 n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${key.hex()}"


def verify_password(password: str, stored: str) -> bool:
    #Constant-time verification against the stored scrypt hash.#
    try:
        algo, n, r, p, salt_hex, key_hex = stored.split("$")
        if algo != "scrypt":
            return False
        expected = bytes.fromhex(key_hex)
        calc = scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt_hex),
                      n=int(n), r=int(r), p=int(p), dklen=len(expected))
        return hmac.compare_digest(calc, expected)
    except (ValueError, TypeError):
        return False
"""

def hash_password(password: str) -> str:
    return(ph.hash(password))

def verify_password(password: str, stored: str) -> bool:
    try:
        return ph.verify(stored, password)
    except VerifyMismatchError:
        return False

def validate_email_address(email: str) -> bool:
    try:
        email_info = validate_email(email, check_deliverability=False)
        return True
    except EmailNotValidError:
        return False

# --------------------------------------------------------- validation ------

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,24}$")



def validate_registration(email: str,password: str, password_again: str) -> str | None:
    #if not EMAIL_RE.match(email or ""):
    if not validate_email_address(email):
        return "Enter a valid email address."
    #if not USERNAME_RE.match(username or ""):
    #    return "Username must be 3–24 characters (letters, digits, . _ -)."
    if len(password) < 12:
        return "Password must be at least 10 characters."
    #if len(password) > 60:
    #    return "Password is too long."
    if not pwd_policy.validate(password):
        return "Password is not valid."
    if password != password_again:
        return "Passwords do not match."
    return None


# ------------------------------------------------------------- users API ---

def get_user_by_email(email: str) -> User | None:
    rows = users("email = ?", [email.strip().lower()], limit=1)
    return rows[0] if rows else None


def get_user_by_id(user_id) -> User | None:
    try:
        return users.get(int(user_id))
    except Exception:
        return None


def email_in_use(email: str) -> bool:
    return bool(get_user_by_email(email))


def register_user(email: str, username: str, password: str) -> User:
    now = datetime.now().isoformat()
    return users.insert({"email": email.strip().lower(),
                         #"username": username,
                         "password_hash": hash_password(password),
                         "created_at": now})


def authenticate(email: str, password: str) -> User | None:
    user = get_user_by_email(email)
    if user and verify_password(password, user.password_hash):
        return user
    return None


# ------------------------------------------------------------- notes API ---

def notes_for(user_id: int) -> list[Note]:
    return notes("user_id = ?", [user_id], order_by="id DESC")


def add_note(user_id: int, body: str) -> Note:
    return notes.insert({"user_id": user_id, "body": body, "created_at": ""})


def delete_note(user_id: int, note_id) -> bool:
    """Delete a note *owned by* user_id. Returns True on success."""
    try:
        note = notes.get(int(note_id))
    except Exception:
        return False
    if note is None or note.user_id != user_id:
        return False
    rows_before = len(notes_for(user_id))
    notes.delete(int(note_id))
    return len(notes_for(user_id)) < rows_before


def count_users() -> int:
    return len(users())


# unique index (belt and braces on top of application-level checks)
db.execute("create unique index if not exists idx_user_email on user(email)")
