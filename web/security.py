"""Panel xavfsizligi: admin hisobi, CSRF, brute-force himoyasi, HTTP sarlavhalari."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import time

from vpnauth import ITERATIONS, hash_password, password_problem, verify_password

from store import STATE_DIR, atomic_write, read_text

ADMIN_FILE = os.path.join(STATE_DIR, "admin.json")
SECRET_FILE = os.path.join(STATE_DIR, "secret_key")

WEAK_DEFAULTS = {"admin", "password", "changeme", "vpn", "12345678", "admin123"}

LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW = 15 * 60      # oyna: 15 daqiqa
LOGIN_LOCKOUT = 15 * 60     # blok muddati

_admin_lock = threading.Lock()
_rate_lock = threading.Lock()
_attempts: dict[str, list[float]] = {}
_locked_until: dict[str, float] = {}


# ------------------------------------------------------------------ secret key


def load_secret_key() -> str:
    """SECRET_KEY env'dan olinadi; berilmagan yoki bo'sh bo'lsa doimiy kalit generatsiya qilinadi.

    Kalit diskda saqlanadi, shunda konteyner qayta ishga tushganda sessiyalar buzilmaydi.
    """
    env_key = (os.environ.get("SECRET_KEY") or "").strip()
    if env_key and env_key not in {"change-this-secret-key", "change-me"} and len(env_key) >= 32:
        return env_key

    stored = read_text(SECRET_FILE).strip()
    if len(stored) >= 43:
        return stored

    generated = secrets.token_urlsafe(48)
    try:
        atomic_write(SECRET_FILE, generated, mode=0o600)
    except OSError:
        pass
    return generated


# ---------------------------------------------------------------- admin hisobi


def _default_admin() -> dict:
    username = (os.environ.get("ADMIN_USER") or "admin").strip() or "admin"
    raw_password = os.environ.get("ADMIN_PASS") or ""
    weak = (
        not raw_password
        or raw_password.lower() in WEAK_DEFAULTS
        or password_problem(raw_password) is not None
    )
    if weak:
        # Boshlang'ich parolni tasodifiy qilamiz va birinchi kirishda almashtirishni talab qilamiz.
        raw_password = secrets.token_urlsafe(12)
        print(
            "\n" + "=" * 66
            + f"\n  DIQQAT: ADMIN_PASS o'rnatilmagan yoki juda zaif.\n"
            + f"  Vaqtinchalik parol: {raw_password}\n"
            + "  Birinchi kirishdan keyin panel parolni almashtirishni talab qiladi.\n"
            + "=" * 66 + "\n",
            flush=True,
        )
        must_change = True
    else:
        must_change = False

    return {
        "username": username,
        "password": hash_password(raw_password),
        "must_change": must_change,
        "updated": int(time.time()),
    }


def load_admin() -> dict:
    with _admin_lock:
        raw = read_text(ADMIN_FILE)
        if raw:
            try:
                data = json.loads(raw)
                if data.get("username") and data.get("password"):
                    return data
            except json.JSONDecodeError:
                pass
        data = _default_admin()
        # Yozib bo'lmasa jim turmaymiz: aks holda har so'rovda yangi parol
        # yaratilib, hech kim kira olmaydigan holat yuzaga keladi.
        atomic_write(ADMIN_FILE, json.dumps(data, indent=2), mode=0o600)
        return data


def save_admin(data: dict) -> None:
    with _admin_lock:
        data["updated"] = int(time.time())
        atomic_write(ADMIN_FILE, json.dumps(data, indent=2), mode=0o600)


def _env_fingerprint(raw_password: str) -> str:
    """ADMIN_PASS ning izi — parolning o'zi saqlanmaydi."""
    return hashlib.sha256(("vpnpanel-env:" + raw_password).encode()).hexdigest()


def sync_admin_from_env() -> str | None:
    """.env dagi ADMIN_PASS o'zgargan bo'lsa, uni qo'llaydi.

    admin.json bir marta yaratilgach ADMIN_PASS butunlay e'tiborsiz qolar edi —
    foydalanuvchi .env ni tahrirlab, hech narsa o'zgarmaganini ko'rardi.

    Panel orqali almashtirilgan parol qaytarib tashlanmaydi: faqat ADMIN_PASS
    qiymatining o'zi o'zgarganda (izi mos kelmaganda) yozib qo'yiladi.
    """
    raw_password = os.environ.get("ADMIN_PASS") or ""
    if not raw_password:
        return None
    if raw_password.lower() in WEAK_DEFAULTS or password_problem(raw_password) is not None:
        return "ADMIN_PASS juda zaif — e'tiborsiz qoldirildi"

    admin = load_admin()
    fingerprint = _env_fingerprint(raw_password)
    if admin.get("env_fingerprint") == fingerprint:
        return None  # o'zgarmagan

    admin["password"] = hash_password(raw_password, ITERATIONS)
    admin["username"] = (os.environ.get("ADMIN_USER") or "admin").strip() or "admin"
    admin["must_change"] = False
    admin["env_fingerprint"] = fingerprint
    save_admin(admin)
    return "ADMIN_PASS .env dan qo'llandi"


def check_admin(username: str, password: str) -> bool:
    admin = load_admin()
    # Ikkala tekshiruv ham har doim bajariladi — javob vaqti bo'yicha username
    # to'g'ri yoki noto'g'riligini aniqlab bo'lmasin.
    user_ok = hmac.compare_digest(username or "", admin["username"])
    pass_ok = verify_password(admin["password"], password or "")
    return user_ok and pass_ok


def set_admin_password(new_password: str) -> None:
    admin = load_admin()
    admin["password"] = hash_password(new_password, ITERATIONS)
    admin["must_change"] = False
    save_admin(admin)


# -------------------------------------------------------------- brute-force


def login_blocked(key: str) -> int:
    """Blok qolgan sekundlarni qaytaradi (0 = bloklanmagan)."""
    with _rate_lock:
        until = _locked_until.get(key, 0)
        remaining = int(until - time.time())
        return max(0, remaining)


def record_login_failure(key: str) -> int:
    now = time.time()
    with _rate_lock:
        hits = [t for t in _attempts.get(key, []) if now - t < LOGIN_WINDOW]
        hits.append(now)
        _attempts[key] = hits
        if len(hits) >= LOGIN_MAX_ATTEMPTS:
            _locked_until[key] = now + LOGIN_LOCKOUT
            _attempts[key] = []
            return 0
        return LOGIN_MAX_ATTEMPTS - len(hits)


def record_login_success(key: str) -> None:
    with _rate_lock:
        _attempts.pop(key, None)
        _locked_until.pop(key, None)


# --------------------------------------------------------------------- CSRF


def issue_csrf(session) -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def csrf_ok(session, submitted: str | None) -> bool:
    expected = session.get("csrf_token")
    return bool(expected) and bool(submitted) and hmac.compare_digest(expected, submitted)


# ----------------------------------------------------------- HTTP sarlavhalar

CSP = (
    "default-src 'self'; "
    "img-src 'self' data:; "
    "style-src 'self' 'unsafe-inline'; "
    "script-src 'self'; "
    "connect-src 'self'; "
    "font-src 'self'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)


def apply_headers(response, https: bool):
    response.headers["Content-Security-Policy"] = CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(), interest-cohort=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers.setdefault("Cache-Control", "no-store")
    if https:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response
