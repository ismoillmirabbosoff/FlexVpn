"""Parol hashlash va username validatsiyasi.

Bu modul ikkala konteynerda ham ishlatiladi:
  - openvpn konteyneri  -> auth.py (auth-user-pass-verify hook)
  - web konteyneri      -> app.py (user yaratish / parol yangilash)

Ikkalasi bir xil formatdan foydalanadi, shuning uchun bitta nusxa saqlanadi.
"""

import base64
import hashlib
import hmac
import os
import re

ALGO = "pbkdf2_sha256"
ITERATIONS = 210_000
SALT_BYTES = 16
DKLEN = 32

# 3-32 belgi, harf/raqam bilan boshlanadi va tugaydi, orasida . _ - bo'lishi mumkin.
# Bu qoida path traversal ("..", "/") va nomlar bilan bog'liq hiylalarni to'sadi.
_USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,30}[A-Za-z0-9]$")
_RESERVED = {"admin", "root", "con", "prn", "aux", "nul"}

MIN_PASSWORD_LEN = 10


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def valid_username(name) -> bool:
    """Fayl nomi sifatida ishlatish xavfsiz bo'lgan usernamelarnigina qabul qiladi."""
    if not isinstance(name, str):
        return False
    if len(name) > 32:
        return False
    if name.lower() in _RESERVED:
        return False
    if "/" in name or "\\" in name or "\0" in name or name.startswith("."):
        return False
    return _USERNAME_RE.match(name) is not None


def password_problem(password) -> str | None:
    """Parol talablarga javob bermasa sababni (o'zbekcha) qaytaradi, aks holda None."""
    if not isinstance(password, str) or not password:
        return "Parol kiritilmadi"
    if len(password) < MIN_PASSWORD_LEN:
        return f"Parol kamida {MIN_PASSWORD_LEN} ta belgidan iborat bo'lishi kerak"
    if len(password) > 128:
        return "Parol juda uzun (maksimal 128 belgi)"
    if password.strip() != password:
        return "Parol boshida yoki oxirida bo'sh joy bo'lmasligi kerak"
    if "\n" in password or "\r" in password:
        return "Parolda yangi qator belgisi bo'lmasligi kerak"
    classes = sum([
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(not c.isalnum() for c in password),
    ])
    if classes < 3:
        return "Parolda kichik harf, katta harf, raqam va belgidan kamida 3 xili bo'lishi kerak"
    return None


def hash_password(password: str, iterations: int = ITERATIONS) -> str:
    salt = os.urandom(SALT_BYTES)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, DKLEN)
    return f"{ALGO}${iterations}${_b64(salt)}${_b64(dk)}"


def is_hashed(record: str) -> bool:
    return bool(record) and record.strip().startswith(ALGO + "$")


def verify_password(record: str, password: str) -> bool:
    """Saqlangan yozuvni parol bilan solishtiradi (constant-time).

    Eski versiyadan qolgan ochiq matnli yozuvlar ham qo'llab-quvvatlanadi, shunda
    hashga o'tish paytida hech kim tizimdan chiqib qolmaydi.
    """
    if not record or not isinstance(password, str):
        return False
    record = record.strip()

    if not is_hashed(record):
        return hmac.compare_digest(record, password)

    try:
        algo, iterations, salt_b64, hash_b64 = record.split("$")
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, int(iterations), len(expected)
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)
