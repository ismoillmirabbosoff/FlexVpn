#!/usr/bin/python3 -IS
"""OpenVPN `auth-user-pass-verify ... via-file` hook.

argv[1] — vaqtinchalik fayl: 1-qator username, 2-qator parol (yoki auth-token).
Chiqish kodi 0 = ruxsat, 1 = rad etish, 2 = qaror fonda (deferred).

Nega deferred: OpenVPN skriptni kutayotganda BUTUN serverni to'xtatadi — boshqa
userlarning paketlari ham ishlanmaydi. PBKDF2 (210k iteratsiya) ~0.2 s oladi va
bu har bir ulanish va soatlik qayta kalit almashishda takrorlanib, paket
yo'qolishiga olib kelardi. Endi skript faylni o'qiydi, fork qiladi va darhol 2
qaytaradi; natija `auth_control_file` ga yoziladi.

Auth-token (server.conf: auth-gen-token ... external-auth): birinchi kirishda
parol tekshiriladi va sessiya yozib qo'yiladi. Keyingi qayta kalit almashish va
qayta ulanishlarda klient parol o'rniga token yuboradi — OpenVPN uning HMAC ini
o'zi tekshiradi, biz esa hisob hali ham faolligini va parol shu sessiyadan
keyin almashtirilmaganini tekshiramiz.
"""

import hashlib
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vpnauth import valid_username, verify_password  # noqa: E402

USERS_DIR = os.environ.get("VPN_USERS_DIR", "/etc/openvpn/users")
STATE_DIR = os.environ.get("VPN_STATE_DIR", "/etc/openvpn/state")
AUTH_LOG = os.path.join(STATE_DIR, "auth.log")
# Token sessiyalari: <sha256(session_id)> -> "username\tparol tekshirilgan vaqt".
# Faqat openvpn konteyneri ishlatadi (web ga ulashilgan state ichida bo'lsa ham).
TOKENS_DIR = os.path.join(STATE_DIR, "authtokens")
# Shu muddat ishlatilmagan sessiya yozuvlari o'chiriladi. auth-gen-token kaliti
# 2*43200 s dan keyin baribir eskiradi, shuning uchun 3 kun yetarli zaxira.
TOKEN_RECORD_TTL = 3 * 86400

TOKEN_OK_STATES = {"Authenticated", "AuthenticatedEmptyUser"}

ALLOW, DENY = "1", "0"


def log(username: str, outcome: str) -> None:
    ip = os.environ.get("untrusted_ip", "-")
    line = f"{int(time.time())}\t{outcome}\t{username or '-'}\t{ip}\n"
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(AUTH_LOG, "a", encoding="utf-8") as fh:
            fh.write(line)
    except OSError:
        pass
    # OpenVPN logiga ham chiqarish, jonli kuzatish uchun.
    print(f"auth: {outcome} user={username or '-'} ip={ip}", file=sys.stderr, flush=True)


def _token_record_path(session_id: str) -> str:
    # session_id base64 ('/' va '+' bo'lishi mumkin) — fayl nomiga hash qilamiz.
    digest = hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:40]
    return os.path.join(TOKENS_DIR, digest)


def _remember_session(session_id: str, username: str) -> None:
    if not session_id:
        return
    try:
        os.makedirs(TOKENS_DIR, mode=0o700, exist_ok=True)
        path = _token_record_path(session_id)
        tmp = f"{path}.{os.getpid()}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(f"{username}\t{time.time():.3f}\n")
        os.replace(tmp, path)
    except OSError:
        pass
    _prune_token_records()


def _prune_token_records() -> None:
    """Eski sessiya yozuvlarini tozalaydi (ko'pi bilan soatiga bir marta)."""
    marker = os.path.join(TOKENS_DIR, ".pruned")
    now = time.time()
    try:
        if now - os.path.getmtime(marker) < 3600:
            return
    except OSError:
        pass
    try:
        with open(marker, "w", encoding="utf-8"):
            pass
        for name in os.listdir(TOKENS_DIR):
            if name.startswith("."):
                continue
            path = os.path.join(TOKENS_DIR, name)
            try:
                if now - os.path.getmtime(path) > TOKEN_RECORD_TTL:
                    os.remove(path)
            except OSError:
                continue
    except OSError:
        pass


def _token_still_valid(session_id: str, username: str, user_file: str) -> bool:
    """Token sessiyasi bizda bormi va parol shundan keyin almashtirilmaganmi."""
    if not session_id:
        return False
    path = _token_record_path(session_id)
    try:
        with open(path, encoding="utf-8") as fh:
            owner, _, since = fh.read().strip().partition("\t")
        authed_at = float(since)
    except (OSError, ValueError):
        return False
    if owner != username:
        return False
    try:
        if os.path.getmtime(user_file) > authed_at:
            return False  # parol (yoki hisob) sessiyadan keyin yangilangan
    except OSError:
        return False
    try:
        os.utime(path)  # faol sessiya — tozalashga tushmasin
    except OSError:
        pass
    return True


def decide(username: str, password: str) -> tuple[str, str]:
    """(ALLOW|DENY, log uchun sabab)."""
    if not valid_username(username):
        return DENY, "invalid-username"

    if os.path.exists(os.path.join(STATE_DIR, "disabled", username)):
        return DENY, "disabled"

    user_file = os.path.join(USERS_DIR, username)
    if not os.path.isfile(user_file):
        return DENY, "unknown-user"

    state = os.environ.get("session_state", "")
    session_id = os.environ.get("session_id", "")

    if state in TOKEN_OK_STATES:
        if _token_still_valid(session_id, username, user_file):
            return ALLOW, "ok-token"
        return DENY, "token-revoked"

    if state and state != "Initial":
        # Expired / Invalid: parol maydonida token turibdi, uni parol bilan
        # solishtirishning ma'nosi yo'q. Rad etamiz — klient tokenni tashlab,
        # asl parol bilan qaytadan urinadi.
        return DENY, f"token-{state.lower()}"

    try:
        with open(user_file, encoding="utf-8") as fh:
            record = fh.read()
    except OSError:
        return DENY, "unreadable-user-file"

    if not verify_password(record, password):
        return DENY, "bad-password"

    _remember_session(session_id, username)
    return ALLOW, "ok"


def _finish(control_file: str, verdict: str, username: str, reason: str) -> None:
    log(username, reason)
    tmp = f"{control_file}.tmp"
    try:
        # Atomar yozuv: OpenVPN faylni yarim yozilgan holda o'qib qolmasin.
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(verdict)
        os.replace(tmp, control_file)
    except OSError:
        try:
            with open(control_file, "w", encoding="utf-8") as fh:
                fh.write(verdict)
        except OSError:
            pass


def main() -> None:
    username = password = ""
    if len(sys.argv) >= 2:
        try:
            # Fayl skript qaytgach o'chiriladi — fork'dan OLDIN o'qib olamiz.
            with open(sys.argv[1], encoding="utf-8") as fh:
                lines = fh.read().split("\n")
            username = lines[0].strip() if lines else ""
            password = lines[1] if len(lines) > 1 else ""
        except OSError:
            log("", "unreadable-credentials-file")
            sys.exit(1)
    else:
        log("", "no-credentials-file")
        sys.exit(1)

    control_file = os.environ.get("auth_control_file", "")
    if not control_file:
        # Eski OpenVPN yoki qo'lda chaqirish — sinxron rejim.
        verdict, reason = decide(username, password)
        log(username, reason)
        sys.exit(0 if verdict == ALLOW else 1)

    sys.stdout.flush()
    sys.stderr.flush()
    try:
        pid = os.fork()
    except OSError:
        verdict, reason = decide(username, password)
        log(username, reason)
        sys.exit(0 if verdict == ALLOW else 1)

    if pid:
        os._exit(2)  # OpenVPN darhol ishini davom ettiradi

    # Bola jarayon: OpenVPN dan ajralamiz va qarorni faylga yozamiz.
    try:
        os.setsid()
    except OSError:
        pass
    try:
        verdict, reason = decide(username, password)
    except Exception as exc:  # har qanday holatda ham javob yozilsin
        verdict, reason = DENY, f"error:{type(exc).__name__}"
    _finish(control_file, verdict, username, reason)
    os._exit(0)


if __name__ == "__main__":
    main()
