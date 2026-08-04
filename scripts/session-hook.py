#!/usr/bin/env python3
"""OpenVPN client-connect / client-disconnect hook.

Ikki narsani yozadi:
  state/lastseen/<user>   — oxirgi faollik vaqti (faolsiz userlarni topish uchun)
  state/sessions.jsonl    — ulanishlar tarixi (panel "So'nggi ulanishlar" bo'limi)

Bu hook hech qachon ulanishni to'xtatmaydi: xatolik bo'lsa ham 0 qaytaradi.
"""

import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vpnauth import valid_username  # noqa: E402

STATE_DIR = os.environ.get("VPN_STATE_DIR", "/etc/openvpn/state")
LASTSEEN_DIR = os.path.join(STATE_DIR, "lastseen")
SESSIONS_LOG = os.path.join(STATE_DIR, "sessions.jsonl")

# Tarix fayli cheksiz o'smasligi uchun chegara.
MAX_SESSION_BYTES = 2 * 1024 * 1024


def _int(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def touch_lastseen(username: str, when: int) -> None:
    os.makedirs(LASTSEEN_DIR, exist_ok=True)
    path = os.path.join(LASTSEEN_DIR, username)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(str(when))
    os.replace(tmp, path)


def append_session(record: dict) -> None:
    os.makedirs(STATE_DIR, exist_ok=True)
    # Fayl juda kattalashsa, oxirgi yarmini qoldirib qisqartiramiz.
    try:
        if os.path.getsize(SESSIONS_LOG) > MAX_SESSION_BYTES:
            with open(SESSIONS_LOG, encoding="utf-8") as fh:
                lines = fh.readlines()
            with open(SESSIONS_LOG, "w", encoding="utf-8") as fh:
                fh.writelines(lines[len(lines) // 2:])
    except OSError:
        pass
    with open(SESSIONS_LOG, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")


def _client_version(raw: str) -> tuple[int, int]:
    """IV_VER ("2.6.9") -> (2, 6). Aniqlab bo'lmasa (0, 0) — hech narsa yubormaymiz."""
    parts = raw.strip().split(".")
    try:
        return int(parts[0]), int(parts[1])
    except (IndexError, ValueError):
        return (0, 0)


def write_client_config(path: str) -> None:
    """Shu klient uchun qo'shimcha sozlamalarni yozadi (per-client push).

    Klientdagi .ovpn faylini o'zgartirmasdan sozlash imkonini beradi — bu
    o'nlab kompyuterga tarqatilgan profillarni qayta ulashib chiqmaslik uchun
    muhim. OpenVPN bu faylni faqat shu ulanish uchun o'qiydi.

    Klient o'zi haqida IV_* o'zgaruvchilarini yuboradi, shuning uchun
    platformaga mos sozlamani tanlay olamiz. Noto'g'ri direktiva yuborsak
    klient ulana olmaydi, shuning uchun faqat aniq bilgan holatda yozamiz.
    """
    lines = []

    platform = (os.environ.get("IV_PLAT") or "").strip().lower()
    version = _client_version(os.environ.get("IV_VER") or "")

    if platform == "win":
        # Windows'da DNS sizishining oldini oladi: tunneldan tashqaridagi
        # DNS serverlariga murojaat bloklanadi. Faqat Windows qo'llab-quvvatlaydi.
        lines.append('push "block-outside-dns"')

    # Tunnel faqat IPv4 beradi. Klientda IPv6 bo'lsa, ikki stekli saytlarga
    # (masalan CloudFront ortidagilar) trafik IPv6 orqali tunneldan TASHQARIDA
    # ketadi va sayt foydalanuvchining haqiqiy davlatini ko'radi.
    # block-ipv6 OpenVPN 2.5 dan mavjud — eski klientga yuborsak u ulana olmaydi,
    # shuning uchun versiyani tekshiramiz.
    if version >= (2, 5):
        lines.append('push "block-ipv6"')

    if not lines:
        return

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def main() -> None:
    event = sys.argv[1] if len(sys.argv) > 1 else "connect"
    username = os.environ.get("common_name") or os.environ.get("username") or ""

    # OpenVPN client-connect ga oxirgi argument sifatida config fayl yo'lini
    # beradi. Foydalanuvchi nomi noto'g'ri bo'lsa ham buni yozib qo'yamiz.
    if event == "connect" and len(sys.argv) > 2:
        try:
            write_client_config(sys.argv[2])
        except OSError as exc:
            print(f"session-hook: client config yozilmadi: {exc}", file=sys.stderr)

    if not valid_username(username):
        return

    now = int(time.time())
    touch_lastseen(username, now)

    record = {
        "event": event,
        "user": username,
        "ts": now,
        "real_ip": (os.environ.get("trusted_ip") or os.environ.get("untrusted_ip") or "").strip(),
        "vpn_ip": os.environ.get("ifconfig_pool_remote_ip", ""),
    }
    if event == "disconnect":
        record["duration"] = _int(os.environ.get("time_duration"))
        record["bytes_received"] = _int(os.environ.get("bytes_received"))
        record["bytes_sent"] = _int(os.environ.get("bytes_sent"))

    append_session(record)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # ulanishni hech qachon buzmaymiz
        print(f"session-hook error: {exc}", file=sys.stderr)
    sys.exit(0)
