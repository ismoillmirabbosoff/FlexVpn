"""Fayl tizimidagi holat bilan ishlash: userlar, metadata, audit log.

Web konteyner bitta gunicorn worker (ko'p thread) bilan ishlaydi, shuning uchun
jarayonlararo lock kerak emas — oddiy threading.Lock yetarli.
"""

from __future__ import annotations

import json
import os
import threading
import time

USERS_DIR = os.environ.get("VPN_USERS_DIR", "/etc/openvpn/users")
STATE_DIR = os.environ.get("VPN_STATE_DIR", "/app/state")
OVPN_DIR = os.environ.get("VPN_OVPN_DIR", "/app/ovpn")

LASTSEEN_DIR = os.path.join(STATE_DIR, "lastseen")
DISABLED_DIR = os.path.join(STATE_DIR, "disabled")
META_FILE = os.path.join(STATE_DIR, "meta.json")
AUDIT_FILE = os.path.join(STATE_DIR, "audit.jsonl")
SESSIONS_FILE = os.path.join(STATE_DIR, "sessions.jsonl")
STATUS_FILE = os.path.join(STATE_DIR, "openvpn-status.log")
CA_FILE = os.path.join(STATE_DIR, "ca.crt")
TA_FILE = os.path.join(STATE_DIR, "ta.key")
SERVER_CRT_FILE = os.path.join(STATE_DIR, "server.crt")
MGMT_PASS_FILE = os.path.join(STATE_DIR, "mgmt.pass")

MAX_AUDIT_BYTES = 1024 * 1024

_meta_lock = threading.Lock()
_audit_lock = threading.Lock()


def ensure_dirs() -> None:
    for path in (STATE_DIR, LASTSEEN_DIR, DISABLED_DIR, OVPN_DIR, USERS_DIR):
        try:
            os.makedirs(path, exist_ok=True)
        except OSError:
            pass


def atomic_write(path: str, content: str, mode: int = 0o640) -> None:
    tmp = f"{path}.tmp.{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(content)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def read_text(path: str, default: str = "") -> str:
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return default


# ------------------------------------------------------------------- metadata


def _load_meta() -> dict:
    raw = read_text(META_FILE)
    if not raw:
        return {"version": 1, "users": {}}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {"version": 1, "users": {}}
    data.setdefault("users", {})
    return data


def get_meta(username: str) -> dict:
    with _meta_lock:
        return dict(_load_meta()["users"].get(username, {}))


def all_meta() -> dict:
    with _meta_lock:
        return _load_meta()["users"]


def update_meta(username: str, **fields) -> None:
    with _meta_lock:
        data = _load_meta()
        entry = data["users"].setdefault(username, {})
        entry.update(fields)
        atomic_write(META_FILE, json.dumps(data, indent=2, ensure_ascii=False))


def drop_meta(username: str) -> None:
    with _meta_lock:
        data = _load_meta()
        if data["users"].pop(username, None) is not None:
            atomic_write(META_FILE, json.dumps(data, indent=2, ensure_ascii=False))


# ---------------------------------------------------------------------- audit


def audit(action: str, actor: str = "system", target: str = "", detail: str = "", ip: str = "") -> None:
    record = {
        "ts": int(time.time()),
        "action": action,
        "actor": actor,
        "target": target,
        "detail": detail,
        "ip": ip,
    }
    with _audit_lock:
        try:
            if os.path.exists(AUDIT_FILE) and os.path.getsize(AUDIT_FILE) > MAX_AUDIT_BYTES:
                with open(AUDIT_FILE, encoding="utf-8") as fh:
                    lines = fh.readlines()
                atomic_write(AUDIT_FILE, "".join(lines[len(lines) // 2:]))
            with open(AUDIT_FILE, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        except OSError:
            pass


def _tail_jsonl(path: str, limit: int) -> list[dict]:
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        return []
    out = []
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
        if len(out) >= limit:
            break
    return out


def recent_audit(limit: int = 200) -> list[dict]:
    return _tail_jsonl(AUDIT_FILE, limit)


def recent_sessions(limit: int = 200) -> list[dict]:
    return _tail_jsonl(SESSIONS_FILE, limit)


# ------------------------------------------------------------------ faollik


def last_seen(username: str) -> int | None:
    raw = read_text(os.path.join(LASTSEEN_DIR, username)).strip()
    if not raw:
        return None
    try:
        return int(float(raw))
    except ValueError:
        return None


def is_disabled(username: str) -> bool:
    return os.path.exists(os.path.join(DISABLED_DIR, username))


def set_disabled(username: str, disabled: bool, reason: str = "") -> None:
    marker = os.path.join(DISABLED_DIR, username)
    if disabled:
        os.makedirs(DISABLED_DIR, exist_ok=True)
        atomic_write(marker, reason or "disabled", mode=0o644)
        update_meta(username, disabled_at=int(time.time()), disabled_reason=reason)
    else:
        try:
            os.remove(marker)
        except FileNotFoundError:
            pass
        update_meta(username, disabled_at=None, disabled_reason="", reactivated_at=int(time.time()))


def list_usernames() -> list[str]:
    if not os.path.isdir(USERS_DIR):
        return []
    names = []
    for name in os.listdir(USERS_DIR):
        if name.startswith(".") or name.endswith(".tmp"):
            continue
        if os.path.isfile(os.path.join(USERS_DIR, name)):
            names.append(name)
    return sorted(names, key=str.lower)


def user_path(username: str) -> str:
    return os.path.join(USERS_DIR, username)


def ovpn_path(username: str) -> str:
    return os.path.join(OVPN_DIR, f"{username}.ovpn")
