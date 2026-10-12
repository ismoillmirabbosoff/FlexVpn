#!/bin/sh
set -e

IFACE=awg0
AWG_MTU="${AWG_MTU:-1280}"
AWG_SUBNET="${AWG_SUBNET:-10.9.0.0/24}"
STATE_DIR="${AWG_STATE_DIR:-/state}/awg"
PUID="${PUID:-1000}"
PGID="${PGID:-1000}"

# peers/ ga web panel (PUID) yozadi, status/server.json ni u o'qiydi.
mkdir -p "$STATE_DIR/peers" /etc/amneziawg
chown "$PUID:$PGID" "$STATE_DIR" "$STATE_DIR/peers"
chmod 750 "$STATE_DIR"
chmod 700 "$STATE_DIR/peers"

# Server kaliti va niqoblash parametrlari (birinchi ishga tushishda yaratiladi,
# keyin o'zgarmaydi — aks holda barcha klient fayllari eskirib qolardi).
python3 /opt/awg/sync.py init

ip link del "$IFACE" 2>/dev/null || true
amneziawg-go -f "$IFACE" &
AWG_PID=$!
for _ in $(seq 1 50); do
    [ -S "/var/run/amneziawg/$IFACE.sock" ] && break
    sleep 0.1
done

python3 /opt/awg/sync.py apply

SERVER_IP="$(python3 -c "import ipaddress,sys; n=ipaddress.ip_network(sys.argv[1]); print(f'{next(n.hosts())}/{n.prefixlen}')" "$AWG_SUBNET")"
ip addr add "$SERVER_IP" dev "$IFACE"
ip link set "$IFACE" mtu "$AWG_MTU" up

DEFAULT_IF="$(ip route show default | awk '/default/ {print $5; exit}')"
add_rule() {
    table=$1; shift
    iptables -t "$table" -C "$@" 2>/dev/null || iptables -t "$table" -A "$@"
}
add_rule nat POSTROUTING -s "$AWG_SUBNET" -o "$DEFAULT_IF" -j MASQUERADE
add_rule filter FORWARD -i "$IFACE" -o "$DEFAULT_IF" -j ACCEPT
add_rule filter FORWARD -i "$DEFAULT_IF" -o "$IFACE" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
# TCP MSS tunnel MTU siga mos: katta paketlar bo'linib yo'qolmasin.
TCP_MSS=$(( AWG_MTU - 40 ))
for dir in -i -o; do
    add_rule mangle FORWARD "$dir" "$IFACE" -p tcp --tcp-flags SYN,RST SYN \
        -m tcpmss --mss "$(( TCP_MSS + 1 )):65535" -j TCPMSS --set-mss "$TCP_MSS"
done

echo "=== AmneziaWG ishga tushdi (udp/${AWG_PORT:-51443}, MTU $AWG_MTU, $AWG_SUBNET) ==="

trap 'kill -TERM "$AWG_PID" 2>/dev/null; exit 0' TERM INT
# Userlar ro'yxatini kuzatib, o'zgarishlarni uzilishsiz qo'llaydi.
python3 /opt/awg/sync.py run "$AWG_PID" &
SYNC_PID=$!
# Ikkalasidan biri to'xtasa konteyner qayta ishga tushsin (restart: unless-stopped).
while kill -0 "$AWG_PID" 2>/dev/null && kill -0 "$SYNC_PID" 2>/dev/null; do
    sleep 2
done
echo "!!! amneziawg-go yoki sync to'xtadi — konteyner qayta ishga tushadi"
kill "$AWG_PID" "$SYNC_PID" 2>/dev/null || true
exit 1
