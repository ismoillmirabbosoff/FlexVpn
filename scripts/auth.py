#!/usr/bin/env python3
"""OpenVPN `auth-user-pass-verify ... via-file` hook.

argv[1] — vaqtinchalik fayl: 1-qator username, 2-qator parol.
Chiqish kodi 0 = ruxsat, 1 = rad etish.
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vpnauth import valid_username, verify_password  # noqa: E402

USERS_DIR = os.environ.get("VPN_USERS_DIR", "/etc/openvpn/users")
STATE_DIR = os.environ.get("VPN_STATE_DIR", "/etc/openvpn/state")
AUTH_LOG = os.path.join(STATE_DIR, "auth.log")


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
    print(f"auth: {outcome} user={username or '-'} ip={ip}", file=sys.stderr)


def deny(username: str, reason: str) -> "None":
    log(username, reason)
    sys.exit(1)


def main() -> None:
    if len(sys.argv) < 2:
        deny("", "no-credentials-file")

    try:
        with open(sys.argv[1], encoding="utf-8") as fh:
            lines = fh.read().split("\n")
    except OSError:
        deny("", "unreadable-credentials-file")

    username = lines[0].strip() if lines else ""
    password = lines[1] if len(lines) > 1 else ""

    if not valid_username(username):
        deny(username, "invalid-username")

    if os.path.exists(os.path.join(STATE_DIR, "disabled", username)):
        deny(username, "disabled")

    user_file = os.path.join(USERS_DIR, username)
    if not os.path.isfile(user_file):
        deny(username, "unknown-user")

    try:
        with open(user_file, encoding="utf-8") as fh:
            record = fh.read()
    except OSError:
        deny(username, "unreadable-user-file")

    if not verify_password(record, password):
        deny(username, "bad-password")

    log(username, "ok")
    sys.exit(0)


if __name__ == "__main__":
    main()
