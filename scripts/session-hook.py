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


def main() -> None:
    event = sys.argv[1] if len(sys.argv) > 1 else "connect"
    username = os.environ.get("common_name") or os.environ.get("username") or ""

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
