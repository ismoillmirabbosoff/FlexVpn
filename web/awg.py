"""AmneziaWG klient profillari.

Har bir user uchun kalit juftligi va tunnel IP manzili state/awg/peers/<user>.json
da saqlanadi. amneziawg konteyneri (awg/sync.py) shu fayllardan peerlarni
serverga qo'yadi — bloklangan va o'chirilgan userlarni o'zi chiqarib tashlaydi.

Klient maxfiy kaliti serverda saqlanadi: .ovpn ichidagi parol kabi, profilni
istalgan vaqtda qayta yuklab olish mumkin bo'lsin.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import os
import threading
import time

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import store

AWG_DIR = os.path.join(store.STATE_DIR, "awg")
PEERS_DIR = os.path.join(AWG_DIR, "peers")
SERVER_JSON = os.path.join(AWG_DIR, "server.json")
STATUS_JSON = os.path.join(AWG_DIR, "status.json")

SUBNET = os.environ.get("AWG_SUBNET", "10.9.0.0/24")
STALE_AFTER = 30

_lock = threading.Lock()


def peer_path(username: str) -> str:
    return os.path.join(PEERS_DIR, f"{username}.json")


def server_info() -> dict | None:
    raw = store.read_text(SERVER_JSON)
    try:
        return json.loads(raw) if raw else None
    except json.JSONDecodeError:
        return None


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _new_keypair() -> tuple[str, str]:
    raw = bytearray(os.urandom(32))
    # Curve25519 "clamping" — `awg genkey` bilan bir xil formatdagi kalit.
    raw[0] &= 248
    raw[31] &= 127
    raw[31] |= 64
    private = X25519PrivateKey.from_private_bytes(bytes(raw))
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return _b64(bytes(raw)), _b64(public)


def _used_ips() -> set[str]:
    used = set()
    try:
        names = os.listdir(PEERS_DIR)
    except OSError:
        return used
    for name in names:
        if not name.endswith(".json"):
            continue
        try:
            used.add(json.loads(store.read_text(os.path.join(PEERS_DIR, name)))["ip"])
        except (ValueError, KeyError, TypeError):
            continue
    return used


def ensure_peer(username: str) -> dict:
    """Userning peer yozuvini qaytaradi; yo'q bo'lsa yaratadi."""
    with _lock:
        existing = store.read_text(peer_path(username))
        if existing:
            try:
                return json.loads(existing)
            except json.JSONDecodeError:
                pass

        net = ipaddress.ip_network(SUBNET)
        used = _used_ips()
        hosts = list(net.hosts())[1:]  # birinchisi — server
        ip = next((str(h) for h in hosts if str(h) not in used), None)
        if ip is None:
            raise RuntimeError("AmneziaWG tarmog'ida bo'sh IP qolmadi")

        private, public = _new_keypair()
        peer = {"private_key": private, "public_key": public, "psk": _b64(os.urandom(32)), "ip": ip}
        os.makedirs(PEERS_DIR, exist_ok=True)
        store.atomic_write(peer_path(username), json.dumps(peer, indent=2), mode=0o600)
        return peer


def remove_peer(username: str) -> None:
    try:
        os.remove(peer_path(username))
    except OSError:
        pass


def render_config(username: str, endpoint_host: str) -> str | None:
    info = server_info()
    if not info:
        return None
    peer = ensure_peer(username)
    params = info.get("params", {})
    lines = [
        f"# FlexVPN — AmneziaWG profili: {username}",
        "[Interface]",
        f"PrivateKey = {peer['private_key']}",
        f"Address = {peer['ip']}/32",
        f"DNS = {', '.join(info.get('dns') or ['1.1.1.1'])}",
        f"MTU = {info.get('mtu', 1280)}",
    ]
    lines += [f"{k} = {v}" for k, v in params.items()]
    lines += [
        "",
        "[Peer]",
        f"PublicKey = {info['public_key']}",
        f"PresharedKey = {peer['psk']}",
        f"Endpoint = {endpoint_host}:{info['port']}",
        # ::/0 ham tunnelga: IPv6 trafik tunneldan tashqarida "sizib" haqiqiy
        # manzilni ko'rsatmasin (server IPv6 bermaydi — saytlar IPv4 ga o'tadi).
        "AllowedIPs = 0.0.0.0/0, ::/0",
        # NAT ortidagi ofis kompyuterlari uchun ulanishni tirik ushlab turadi.
        "PersistentKeepalive = 25",
    ]
    return "\n".join(lines) + "\n"


def status() -> dict[str, dict]:
    """{user: {...}} — faqat status yangi bo'lsa (awg konteyneri ishlayapti)."""
    try:
        if time.time() - os.path.getmtime(STATUS_JSON) > STALE_AFTER:
            return {}
        return json.loads(store.read_text(STATUS_JSON)).get("peers", {})
    except (OSError, ValueError):
        return {}
