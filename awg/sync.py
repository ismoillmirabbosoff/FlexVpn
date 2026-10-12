#!/usr/bin/python3 -I
"""AmneziaWG serverini panel holati bilan sinxronlaydi.

  sync.py init        — server kaliti va niqoblash parametrlarini yaratadi (bir marta)
  sync.py apply       — peerlarni bir marta qo'llaydi
  sync.py run <pid>   — doimiy sikl: peerlar + status + lastseen

Panel (web konteyner) state/awg/peers/<user>.json ga klient kalitini yozadi.
Bu skript ulardan faqat mavjud va bloklanmagan userlarni serverga qo'yadi.
`awg syncconf` o'zgarmagan peerlarning sessiyasiga tegmaydi — user qo'shish yoki
bloklash boshqalarni uzmaydi. Bloklangan/o'chirilgan user darhol uziladi.
"""

import hashlib
import ipaddress
import json
import os
import random
import subprocess
import sys
import time

IFACE = "awg0"
CONF_DIR = "/etc/amneziawg"
STATE_DIR = os.environ.get("AWG_STATE_DIR", "/state")
AWG_DIR = os.path.join(STATE_DIR, "awg")
PEERS_DIR = os.path.join(AWG_DIR, "peers")
SERVER_JSON = os.path.join(AWG_DIR, "server.json")
STATUS_JSON = os.path.join(AWG_DIR, "status.json")
USERS_DIR = os.environ.get("AWG_USERS_DIR", "/users")
DISABLED_DIR = os.path.join(STATE_DIR, "disabled")
LASTSEEN_DIR = os.path.join(STATE_DIR, "lastseen")
SESSIONS_LOG = os.path.join(STATE_DIR, "sessions.jsonl")

PORT = int(os.environ.get("AWG_PORT", "51443"))
MTU = int(os.environ.get("AWG_MTU", "1280"))
SUBNET = os.environ.get("AWG_SUBNET", "10.9.0.0/24")
DNS = [d for d in (os.environ.get("VPN_DNS1", "1.1.1.1"), os.environ.get("VPN_DNS2", "8.8.8.8")) if d]
PUID = int(os.environ.get("PUID", "1000"))
PGID = int(os.environ.get("PGID", "1000"))

# Parametrlar oldindan taxmin qilinmasin.
random = random.SystemRandom()

SYNC_INTERVAL = 3
ONLINE_WINDOW = 180          # oxirgi handshake shundan yangi bo'lsa — ulangan
LASTSEEN_REFRESH = 600


def _write(path: str, content: str, mode: int = 0o640, owner: bool = False) -> None:
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(content)
    os.chmod(tmp, mode)
    if owner:
        try:
            os.chown(tmp, PUID, PGID)
        except OSError:
            pass
    os.replace(tmp, path)


def _awg(*args: str, stdin: str | None = None) -> str:
    return subprocess.run(["awg", *args], input=stdin, capture_output=True,
                          text=True, check=True).stdout.strip()


# ------------------------------------------------------------------ init


def _header_ranges() -> list[str]:
    """H1-H4: bir-biriga kesishmaydigan tasodifiy oraliqlar (WireGuard'ning
    1-4 qiymatli ochiq sarlavhalari o'rniga — DPI uchun eng aniq belgi)."""
    lo_limit, hi_limit = 5, 2**31 - 1
    quarter = (hi_limit - lo_limit) // 4
    ranges = []
    for i in range(4):
        start = lo_limit + i * quarter
        width = random.randint(10_000_000, 100_000_000)
        lo = random.randint(start, start + quarter - width - 1)
        ranges.append(f"{lo}-{lo + width}")
    random.shuffle(ranges)
    return ranges


def _quic_like_signature() -> str:
    """I1: handshake'dan oldin yuboriladigan, QUIC Initial paketiga o'xshash paket.
    Jami 1200 bayt — haqiqiy QUIC Initial o'lchami; MTU dan kichik."""
    return "<b 0xc300000001><b 0x08><r 8><b 0x00><b 0x00><b 0x449e><r 1182>"


def _new_params() -> dict:
    jmin = random.randint(40, 70)
    s1 = random.randint(20, 120)
    s2 = random.randint(20, 120)
    while s1 + 56 == s2:
        s2 = random.randint(20, 120)
    h = _header_ranges()
    return {
        "Jc": random.randint(4, 8),
        "Jmin": jmin,
        "Jmax": jmin + random.randint(200, 600),
        "S1": s1,
        "S2": s2,
        "S3": random.randint(20, 80),
        # Har bir transport paketiga qo'shimcha — kichik bo'lsin (tezlik).
        "S4": random.randint(8, 24),
        "H1": h[0], "H2": h[1], "H3": h[2], "H4": h[3],
        "I1": _quic_like_signature(),
    }


def init() -> None:
    key_file = os.path.join(CONF_DIR, "server.key")
    params_file = os.path.join(CONF_DIR, "params.json")

    if not os.path.isfile(key_file):
        _write(key_file, _awg("genkey") + "\n", mode=0o600)
    if not os.path.isfile(params_file):
        _write(params_file, json.dumps(_new_params(), indent=2) + "\n", mode=0o600)

    private = open(key_file, encoding="utf-8").read().strip()
    params = json.load(open(params_file, encoding="utf-8"))
    info = {
        "public_key": _awg("pubkey", stdin=private + "\n"),
        "port": PORT,
        "mtu": MTU,
        "subnet": SUBNET,
        "dns": DNS,
        "params": params,
    }
    _write(SERVER_JSON, json.dumps(info, indent=2) + "\n", mode=0o644, owner=True)


# ----------------------------------------------------------------- peers


def _wanted_peers() -> dict[str, dict]:
    net = ipaddress.ip_network(SUBNET)
    peers = {}
    try:
        names = os.listdir(PEERS_DIR)
    except OSError:
        return peers
    for name in names:
        if not name.endswith(".json") or name.startswith("."):
            continue
        user = name[:-5]
        if not os.path.isfile(os.path.join(USERS_DIR, user)):
            continue  # o'chirilgan user
        if os.path.exists(os.path.join(DISABLED_DIR, user)):
            continue  # bloklangan user
        try:
            data = json.load(open(os.path.join(PEERS_DIR, name), encoding="utf-8"))
            ip = ipaddress.ip_address(data["ip"])
            if ip not in net:
                continue
            peers[user] = {"public_key": data["public_key"], "psk": data["psk"], "ip": str(ip)}
        except (OSError, ValueError, KeyError, TypeError):
            continue
    return peers


def _render_conf(peers: dict[str, dict]) -> str:
    private = open(os.path.join(CONF_DIR, "server.key"), encoding="utf-8").read().strip()
    params = json.load(open(os.path.join(CONF_DIR, "params.json"), encoding="utf-8"))
    lines = ["[Interface]", f"PrivateKey = {private}", f"ListenPort = {PORT}"]
    lines += [f"{k} = {v}" for k, v in params.items()]
    for user in sorted(peers):
        p = peers[user]
        lines += ["", f"# {user}", "[Peer]", f"PublicKey = {p['public_key']}",
                  f"PresharedKey = {p['psk']}", f"AllowedIPs = {p['ip']}/32"]
    return "\n".join(lines) + "\n"


def apply(force: bool = False, _state: dict = {}) -> dict[str, dict]:
    peers = _wanted_peers()
    conf = _render_conf(peers)
    digest = hashlib.sha256(conf.encode()).hexdigest()
    if force or digest != _state.get("digest"):
        path = "/run/awg0.conf"
        _write(path, conf, mode=0o600)
        _awg("syncconf", IFACE, path)
        if _state.get("digest"):
            print(f"awg: peerlar yangilandi ({len(peers)} ta faol)", flush=True)
        _state["digest"] = digest
    return peers


# ---------------------------------------------------------------- status


def _dump() -> dict[str, dict]:
    """awg show dump -> {public_key: {...}}"""
    out = _awg("show", IFACE, "dump").splitlines()[1:]
    result = {}
    for line in out:
        cols = line.split("\t")
        if len(cols) < 8:
            continue
        result[cols[0]] = {
            "endpoint": "" if cols[2] == "(none)" else cols[2],
            "latest_handshake": int(cols[4] or 0),
            "rx": int(cols[5] or 0),
            "tx": int(cols[6] or 0),
        }
    return result


def _append_session(record: dict) -> None:
    try:
        with open(SESSIONS_LOG, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass


def status(peers: dict[str, dict], memory: dict) -> None:
    now = int(time.time())
    dump = _dump()
    online_now = {}
    entries = {}
    for user, p in peers.items():
        d = dump.get(p["public_key"], {})
        hs = d.get("latest_handshake", 0)
        online = bool(hs) and now - hs < ONLINE_WINDOW
        entries[user] = {"ip": p["ip"], "online": online, **d}
        if online:
            online_now[user] = entries[user]

    # Ulanish/uzilish tarixini panelning "So'nggi ulanishlar" bo'limiga yozamiz.
    before = memory.setdefault("online", {})
    for user, e in online_now.items():
        if user not in before:
            memory.setdefault("since", {})[user] = now
            _append_session({"event": "connect", "user": user, "ts": now, "proto": "awg",
                             "real_ip": e.get("endpoint", "").rsplit(":", 1)[0], "vpn_ip": e["ip"]})
    for user, e in before.items():
        if user not in online_now:
            since = memory.get("since", {}).pop(user, now)
            _append_session({"event": "disconnect", "user": user, "ts": now, "proto": "awg",
                             "real_ip": e.get("endpoint", "").rsplit(":", 1)[0], "vpn_ip": e["ip"],
                             "duration": now - since, "bytes_received": e.get("rx", 0),
                             "bytes_sent": e.get("tx", 0)})
    memory["online"] = online_now
    for user in entries:
        entries[user]["connected_since"] = memory.get("since", {}).get(user, 0)

    # Faol userlar janitor tomonidan "faolsiz" deb bloklanmasin.
    written = memory.setdefault("lastseen", {})
    for user in online_now:
        if now - written.get(user, 0) >= LASTSEEN_REFRESH:
            try:
                os.makedirs(LASTSEEN_DIR, exist_ok=True)
                _write(os.path.join(LASTSEEN_DIR, user), str(now), mode=0o644, owner=True)
                written[user] = now
            except OSError:
                pass

    _write(STATUS_JSON, json.dumps({"ts": now, "peers": entries}) + "\n", mode=0o644, owner=True)


def run(awg_pid: int) -> None:
    memory: dict = {}
    while True:
        try:
            os.kill(awg_pid, 0)
        except OSError:
            sys.exit(1)
        try:
            peers = apply()
            status(peers, memory)
        except Exception as exc:  # sikl hech qachon to'xtamasin
            print(f"awg sync xatosi: {exc}", flush=True)
        time.sleep(SYNC_INTERVAL)


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "init":
        init()
    elif cmd == "apply":
        apply(force=True)
    elif cmd == "run":
        run(int(sys.argv[2]))
    else:
        sys.exit("usage: sync.py init|apply|run <pid>")
