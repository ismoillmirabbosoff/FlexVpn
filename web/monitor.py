"""OpenVPN holatini kuzatish: jonli klientlar, tezlik, trafik, faolsiz userlarni tozalash."""

from __future__ import annotations

import json
import os
import socket
import threading
import time
from collections import deque

import store

SAMPLE_INTERVAL = 5          # status fayli har 5 sekundda yangilanadi
HISTORY_POINTS = 180         # 180 * 5s = 15 daqiqalik grafik
STALE_AFTER = 30             # status fayli shundan eski bo'lsa server o'chgan deb hisoblaymiz

MGMT_HOST = os.environ.get("VPN_MGMT_HOST", "openvpn")
MGMT_PORT = int(os.environ.get("VPN_MGMT_PORT", "7505"))

INACTIVE_DISABLE_DAYS = int(os.environ.get("INACTIVE_DISABLE_DAYS", "30"))
INACTIVE_DELETE_DAYS = int(os.environ.get("INACTIVE_DELETE_DAYS", "45"))
JANITOR_INTERVAL = int(os.environ.get("JANITOR_INTERVAL", "3600"))

_lock = threading.Lock()
_clients: dict[str, dict] = {}
_history: deque = deque(maxlen=HISTORY_POINTS)
_prev_sample: dict[str, tuple[float, int, int]] = {}
_server_online = False
_last_poll = 0.0


# --------------------------------------------------------------- status fayli


def _parse_status(text: str) -> list[dict]:
    """status-version 3 (tab bilan ajratilgan) formatini o'qiydi."""
    headers: dict[str, list[str]] = {}
    clients: list[dict] = []

    for line in text.splitlines():
        if not line:
            continue
        parts = line.split("\t")
        tag = parts[0]

        if tag == "HEADER" and len(parts) > 2:
            headers[parts[1]] = parts[2:]
        elif tag == "CLIENT_LIST":
            cols = headers.get("CLIENT_LIST", [])
            row = dict(zip(cols, parts[1:]))
            name = row.get("Common Name") or row.get("Username") or ""
            if not name or name == "UNDEF":
                continue
            clients.append({
                "name": name,
                "real_address": row.get("Real Address", ""),
                "vpn_address": row.get("Virtual Address", ""),
                "bytes_received": _int(row.get("Bytes Received")),
                "bytes_sent": _int(row.get("Bytes Sent")),
                "connected_since": _int(row.get("Connected Since (time_t)")),
                "cipher": row.get("Data Channel Cipher", ""),
            })
    return clients


def _int(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def poll_once() -> None:
    """Status faylini o'qib jonli tezlikni hisoblaydi. Sampler thread chaqiradi."""
    global _server_online, _last_poll

    now = time.time()
    try:
        fresh = (now - os.path.getmtime(store.STATUS_FILE)) < STALE_AFTER
        text = store.read_text(store.STATUS_FILE)
    except OSError:
        fresh, text = False, ""

    clients = _parse_status(text) if fresh else []

    total_down = total_up = 0.0
    seen = set()
    for client in clients:
        name = client["name"]
        seen.add(name)
        prev = _prev_sample.get(name)
        # Yangi ulanishda hisoblagich noldan boshlanadi — eski qiymat bilan
        # solishtirsak, tezlik keskin sakraydi. Shuning uchun kamayishni 0 deb olamiz.
        if prev and now > prev[0]:
            elapsed = now - prev[0]
            down = max(0, client["bytes_received"] - prev[1]) / elapsed
            up = max(0, client["bytes_sent"] - prev[2]) / elapsed
        else:
            down = up = 0.0
        client["down_bps"] = down * 8
        client["up_bps"] = up * 8
        total_down += down * 8
        total_up += up * 8
        _prev_sample[name] = (now, client["bytes_received"], client["bytes_sent"])

    for name in list(_prev_sample):
        if name not in seen:
            _prev_sample.pop(name, None)

    with _lock:
        _server_online = fresh
        _clients.clear()
        _clients.update({c["name"]: c for c in clients})
        _history.append({"ts": int(now), "down": round(total_down), "up": round(total_up)})
        _last_poll = now


def live_clients() -> list[dict]:
    with _lock:
        return sorted(_clients.values(), key=lambda c: c["connected_since"])


def is_online(username: str) -> bool:
    with _lock:
        return username in _clients


def server_online() -> bool:
    with _lock:
        return _server_online


def throughput_history() -> list[dict]:
    with _lock:
        return list(_history)


def current_throughput() -> dict:
    with _lock:
        latest = _history[-1] if _history else {"down": 0, "up": 0}
        return {"down": latest["down"], "up": latest["up"]}


# ------------------------------------------------------------------- trafik


def traffic_summary() -> dict:
    """Yakunlangan sessiyalar + hozirgi jonli sessiyalardan umumiy trafik."""
    day_start = time.time() - 86400
    total = today = 0
    for record in store.recent_sessions(2000):
        if record.get("event") != "disconnect":
            continue
        volume = _int(record.get("bytes_received")) + _int(record.get("bytes_sent"))
        total += volume
        if record.get("ts", 0) >= day_start:
            today += volume
    for client in live_clients():
        volume = client["bytes_received"] + client["bytes_sent"]
        total += volume
        today += volume
    return {"total": total, "today": today}


# --------------------------------------------------- management interfeysi


def _mgmt_command(command: str, timeout: float = 4.0) -> str:
    password = store.read_text(store.MGMT_PASS_FILE).strip()
    with socket.create_connection((MGMT_HOST, MGMT_PORT), timeout=timeout) as sock:
        sock.settimeout(timeout)
        buffer = b""

        def pump(deadline: float) -> None:
            nonlocal buffer
            while time.time() < deadline:
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    return
                if not chunk:
                    return
                buffer += chunk
                if buffer.endswith(b"\r\n") or b"END\r\n" in buffer or b"SUCCESS" in buffer:
                    return

        pump(time.time() + 1.5)
        if b"ENTER PASSWORD" in buffer:
            sock.sendall(password.encode() + b"\n")
            buffer = b""
            pump(time.time() + 1.5)

        buffer = b""
        sock.sendall(command.encode() + b"\n")
        pump(time.time() + timeout)
        return buffer.decode("utf-8", "replace")


def disconnect_client(username: str) -> tuple[bool, str]:
    try:
        reply = _mgmt_command(f"kill {username}")
    except (OSError, socket.timeout) as exc:
        return False, f"Management interfeysiga ulanib bo'lmadi: {exc}"
    if "SUCCESS" in reply:
        return True, "Ulanish uzildi"
    if "ERROR" in reply:
        return False, "Bu foydalanuvchi hozir ulanmagan"
    return False, reply.strip() or "Noma'lum javob"


# ------------------------------------------------------------- server info


def server_info() -> dict:
    raw = store.read_text(os.path.join(store.STATE_DIR, "server_info.json"))
    try:
        info = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        info = {}
    info["online"] = server_online()
    started = _int(info.get("started_at"))
    info["uptime"] = int(time.time() - started) if started and info["online"] else 0
    return info


def ca_expiry() -> dict | None:
    """CA sertifikati muddati. `cryptography` yo'q bo'lsa None qaytaradi."""
    try:
        from cryptography import x509
    except ImportError:
        return None
    raw = store.read_text(store.CA_FILE)
    if not raw:
        return None
    try:
        cert = x509.load_pem_x509_certificate(raw.encode())
        expires = cert.not_valid_after_utc.timestamp()
    except Exception:
        return None
    return {"expires": int(expires), "days_left": int((expires - time.time()) // 86400)}


# ------------------------------------------------ faolsiz userlarni tozalash


def user_activity(username: str) -> dict:
    """Foydalanuvchining faollik holati va avtomatik tozalashgacha qolgan kunlar."""
    now = time.time()
    meta = store.get_meta(username)
    seen = store.last_seen(username)

    if is_online(username):
        seen = int(now)

    # Hech qachon ulanmagan bo'lsa, hisob ochilgan sanadan boshlab hisoblaymiz.
    reference = seen or _int(meta.get("created")) or int(now)
    idle_days = max(0, int((now - reference) // 86400))

    disabled = store.is_disabled(username)
    if disabled:
        days_to_delete = max(0, INACTIVE_DELETE_DAYS - idle_days)
    else:
        days_to_delete = None

    return {
        "last_seen": seen,
        "never_connected": seen is None,
        "created": _int(meta.get("created")) or None,
        "idle_days": idle_days,
        "disabled": disabled,
        "disabled_reason": meta.get("disabled_reason", ""),
        "days_to_disable": max(0, INACTIVE_DISABLE_DAYS - idle_days) if not disabled else 0,
        "days_to_delete": days_to_delete,
        "online": is_online(username),
    }


def run_janitor() -> dict:
    """30 kun faolsiz -> bloklash, 45 kun -> o'chirish. Idempotent."""
    disabled_now, deleted_now = [], []

    for username in store.list_usernames():
        activity = user_activity(username)
        if activity["online"]:
            continue

        idle = activity["idle_days"]
        if not activity["disabled"] and idle >= INACTIVE_DISABLE_DAYS:
            store.set_disabled(username, True, f"{idle} kun faolsiz")
            store.audit("auto_disable", target=username, detail=f"{idle} kun faolsiz")
            disconnect_client(username)
            disabled_now.append(username)
        elif activity["disabled"] and idle >= INACTIVE_DELETE_DAYS:
            _delete_user_files(username)
            store.audit("auto_delete", target=username, detail=f"{idle} kun faolsiz")
            deleted_now.append(username)

    return {"disabled": disabled_now, "deleted": deleted_now}


def _delete_user_files(username: str) -> None:
    for path in (
        store.user_path(username),
        store.ovpn_path(username),
        os.path.join(store.DISABLED_DIR, username),
        os.path.join(store.LASTSEEN_DIR, username),
    ):
        try:
            os.remove(path)
        except OSError:
            pass
    store.drop_meta(username)


# ------------------------------------------------------------ fon threadlari


def _sampler_loop() -> None:
    while True:
        try:
            poll_once()
        except Exception as exc:  # kuzatuv hech qachon panelni o'ldirmasin
            print(f"sampler error: {exc}", flush=True)
        time.sleep(SAMPLE_INTERVAL)


def _janitor_loop() -> None:
    # Ishga tushgandan keyin biroz kutamiz: birinchi status o'qilib bo'lsin.
    time.sleep(30)
    while True:
        try:
            result = run_janitor()
            if result["disabled"] or result["deleted"]:
                print(f"janitor: {result}", flush=True)
        except Exception as exc:
            print(f"janitor error: {exc}", flush=True)
        time.sleep(JANITOR_INTERVAL)


_started = False


def start_background() -> None:
    global _started
    if _started:
        return
    _started = True
    threading.Thread(target=_sampler_loop, daemon=True, name="vpn-sampler").start()
    threading.Thread(target=_janitor_loop, daemon=True, name="vpn-janitor").start()
