#!/bin/bash
set -e

OVPN_DIR="/etc/openvpn"
PKI_DIR="$OVPN_DIR/pki"
STATE_DIR="$OVPN_DIR/state"
SCRIPTS_DIR="/opt/vpn-scripts"
EASYRSA="/usr/share/easy-rsa/easyrsa"

VPN_SUBNET="${VPN_SUBNET:-10.8.0.0}"
VPN_NETMASK="${VPN_NETMASK:-255.255.255.0}"
VPN_PORT="${VPN_PORT:-1194}"
VPN_PROTO="${VPN_PROTO:-udp}"
VPN_DNS1="${VPN_DNS1:-1.1.1.1}"
VPN_DNS2="${VPN_DNS2:-8.8.8.8}"
VPN_MAX_CLIENTS="${VPN_MAX_CLIENTS:-100}"
VPN_MSSFIX="${VPN_MSSFIX:-1360}"
# Tunnel MTU fizik interfeys MTU sidan past bo'lishi SHART: OpenVPN har paketga
# ~60 bayt qo'shadi (IP 20 + UDP 8 + header + AES-GCM tegi 16 + paket raqami).
# 1500 qoldirilsa paketlar fragmentga bo'linadi yoki umuman yo'qoladi — natijada
# tezlik tushadi va uzun TCP oqimlari uziladi. 1420 PPPoE/ISP qo'shimchasiga ham
# joy qoldiradi.
VPN_TUN_MTU="${VPN_TUN_MTU:-1420}"

# Bitta hisob bilan bir nechta qurilmadan (telefon + noutbuk) ulanish.
# 0 bo'lsa: ikkinchi ulanish birinchisini uzib tashlaydi va ikki qurilma
# navbatma-navbat bir-birini uzib turadi — logda "bad packet ID (replay)"
# xatolari to'planadi.
VPN_DUPLICATE_CN="${VPN_DUPLICATE_CN:-1}"
VPN_REDIRECT_GATEWAY="${VPN_REDIRECT_GATEWAY:-1}"
VPN_DCO="${VPN_DCO:-auto}"

# Web konteyner shu uid/gid bilan ishlaydi. State katalogi o'sha egaga beriladi,
# shunda ikkala konteyner ham bir xil fayllar bilan ishlay oladi.
PUID="${PUID:-1000}"
PGID="${PGID:-1000}"

mkdir -p "$STATE_DIR/lastseen" "$STATE_DIR/disabled" "$OVPN_DIR/users"

# Netmask -> prefix (255.255.255.0 -> 24), tashqi utilitalarsiz.
netmask_to_prefix() {
    local bits=0 octet
    for octet in ${1//./ }; do
        while [ "$octet" -gt 0 ]; do
            bits=$(( bits + (octet & 1) ))
            octet=$(( octet >> 1 ))
        done
    done
    echo "$bits"
}

# ---------------------------------------------------------------- sertifikatlar
if [ ! -f "$OVPN_DIR/ta.key" ]; then
    echo "=== Server sertifikatlari yaratilmoqda ==="
    rm -rf "$PKI_DIR"

    cd "$OVPN_DIR"
    export EASYRSA_PKI="$PKI_DIR"
    export EASYRSA_BATCH=1
    export EASYRSA_CA_EXPIRE="${EASYRSA_CA_EXPIRE:-3650}"
    export EASYRSA_CERT_EXPIRE="${EASYRSA_CERT_EXPIRE:-3650}"

    $EASYRSA init-pki
    $EASYRSA build-ca nopass
    $EASYRSA gen-dh
    $EASYRSA gen-req server nopass
    $EASYRSA sign-req server server

    openvpn --genkey secret "$OVPN_DIR/ta.key" 2>/dev/null \
        || openvpn --genkey --secret "$OVPN_DIR/ta.key"

    echo "=== Sertifikatlar tayyor ==="
fi

# Management interfeysi paroli — web panel shu orqali ulanishni uzadi.
# 7505-port hostga chiqarilmaydi, faqat compose tarmog'i ichida ko'rinadi.
MGMT_PASS_FILE="$STATE_DIR/mgmt.pass"
if [ ! -s "$MGMT_PASS_FILE" ]; then
    head -c 24 /dev/urandom | base64 | tr -d '\n=/+' > "$MGMT_PASS_FILE"
    echo >> "$MGMT_PASS_FILE"
fi
chmod 640 "$MGMT_PASS_FILE"

# ------------------------------------------------------------------ tezlashtirish
# DCO (Data Channel Offload) shifrlashni yadro ichida bajaradi va o'tkazuvchanlikni
# bir necha barobar oshiradi. Faqat host yadrosida ovpn moduli yuklangan bo'lsa
# yoqamiz — aks holda openvpn umuman ishga tushmasligi mumkin.
DCO_FLAG="--disable-dco"
DCO_STATE="off"
DCO_REASON=""

if [ "$VPN_DCO" = "0" ]; then
    DCO_REASON="VPN_DCO=0 (qo'lda o'chirilgan)"
elif ! openvpn --version 2>/dev/null | grep -q '\[DCO\]'; then
    # Paket DCO'siz yig'ilgan — flagni bersak ham foyda yo'q.
    DCO_REASON="openvpn paketi DCO'siz yig'ilgan ($(openvpn --version 2>/dev/null | head -1 | awk '{print $2}'))"
elif [ -d /sys/module/ovpn ] || [ -d /sys/module/ovpn_dco_v2 ] || [ -c /dev/ovpn ]; then
    DCO_FLAG=""
    DCO_STATE="on"
else
    DCO_REASON="hostda ovpn yadro moduli yuklanmagan -> hostda bajaring: sudo modprobe ovpn"
fi

if [ "$DCO_STATE" = "on" ]; then
    echo "=== DCO: YOQILGAN (shifrlash yadro darajasida) ==="
else
    echo "=== DCO: o'chiq — $DCO_REASON ==="
    [ "$VPN_DCO" = "1" ] && echo "!!! VPN_DCO=1 so'ralgan edi, lekin yoqib bo'lmadi"
fi

# DCO yoqilganda bu opsiyalarni yadro boshqaradi va openvpn ularni e'tiborsiz
# qoldiradi, shuning uchun faqat DCO o'chiq bo'lganda yozamiz.
TUNING=""
if [ "$DCO_STATE" = "off" ]; then
    TUNING=$(cat <<'TUNEOF'
# --- o'tkazuvchanlik sozlamalari (faqat DCO o'chiq bo'lganda) ---
# fast-io 2.7 da olib tashlangan — epoll allaqachon standart.
sndbuf 0
rcvbuf 0
push "sndbuf 0"
push "rcvbuf 0"
txqueuelen 1000
TUNEOF
)
fi

REDIRECT_LINE=""
if [ "$VPN_REDIRECT_GATEWAY" = "1" ]; then
    REDIRECT_LINE='push "redirect-gateway def1 bypass-dhcp"'
fi

DUPLICATE_LINE=""
if [ "$VPN_DUPLICATE_CN" = "1" ]; then
    DUPLICATE_LINE="duplicate-cn"
fi

# ------------------------------------------------------------------ server config
cat > "$OVPN_DIR/server.conf" <<EOF
port $VPN_PORT
proto $VPN_PROTO
dev tun

ca $PKI_DIR/ca.crt
cert $PKI_DIR/issued/server.crt
key $PKI_DIR/private/server.key
dh $PKI_DIR/dh.pem
tls-auth $OVPN_DIR/ta.key 0
tls-version-min 1.2

topology subnet
server $VPN_SUBNET $VPN_NETMASK
ifconfig-pool-persist $STATE_DIR/ipp.txt 0

$REDIRECT_LINE
push "dhcp-option DNS $VPN_DNS1"
push "dhcp-option DNS $VPN_DNS2"

$TUNING
# Fragmentatsiya tezlikni eng ko'p yeydigan omil — MSS ni oldindan cheklaymiz.
tun-mtu $VPN_TUN_MTU
mssfix $VPN_MSSFIX
# 2.6+ klientlar MTU ni serverdan oladi; eskilari uchun bir xil qiymat .ovpn
# faylining o'ziga ham yoziladi, shunda ikki tomon kelishmovchiligi bo'lmaydi.
push "tun-mtu $VPN_TUN_MTU"
# Siqish VORACLE hujumiga yo'l ochadi va zamonaviy trafikda foyda bermaydi.
allow-compression no

# --- NAT ortidagi ko'p klient uchun barqarorlik ------------------------------
# Ofisdagi o'nlab kompyuter bitta tashqi IP ortida turadi. Router UDP
# moslashuvini (mapping) qayta ishlatganda klientning manba porti o'zgaradi.
# float bo'lmasa server bunday paketlarni begona deb rad etadi va sessiya
# uziladi — foydalanuvchi uchun bu "3 daqiqada chiqib ketdi" bo'lib ko'rinadi.
float

# Ping oralig'i NAT moslashuvini tirik ushlab turadi. 120 soniya ko'p routerlar
# uchun juda uzun — moslashuv undan oldin yopilib qoladi.
keepalive 10 60

# Kengaytirilgan replay oynasi: yuqori kechikish va paket tartibsizligida
# to'g'ri paketlar "replay" deb rad etilmasin.
replay-window 512 60

cipher AES-256-GCM
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
auth SHA256

# Klient sertifikati yo'q: kirish faqat login/parol orqali.
# Parollar pbkdf2-sha256 bilan hashlangan holda saqlanadi (scripts/auth.py).
verify-client-cert none
username-as-common-name
script-security 2
auth-user-pass-verify $SCRIPTS_DIR/auth.py via-file
client-connect "$SCRIPTS_DIR/session-hook.py connect"
client-disconnect "$SCRIPTS_DIR/session-hook.py disconnect"

management 0.0.0.0 7505 $MGMT_PASS_FILE

max-clients $VPN_MAX_CLIENTS
$DUPLICATE_LINE
# persist-key 2.7 da olib tashlangan — kalitlar doim saqlanadi.
persist-tun
status $STATE_DIR/openvpn-status.log 5
status-version 3
verb 3
EOF

# Web panelga faqat ochiq sertifikatlar kerak (.ovpn yaratish va muddatni ko'rsatish
# uchun). Server maxfiy kaliti umuman ulashilmaydi — shuning uchun pki katalogini
# mount qilish o'rniga kerakli ikki faylni state ichiga nusxalaymiz.
cp -f "$PKI_DIR/ca.crt" "$STATE_DIR/ca.crt"
cp -f "$OVPN_DIR/ta.key" "$STATE_DIR/ta.key"
cp -f "$PKI_DIR/issued/server.crt" "$STATE_DIR/server.crt" 2>/dev/null || true

# Panel serverning haqiqiy sozlamalarini ko'rsatishi uchun.
cat > "$STATE_DIR/server_info.json" <<EOF
{
  "started_at": $(date +%s),
  "version": "$(openvpn --version 2>/dev/null | head -1 | awk '{print $2}')",
  "port": $VPN_PORT,
  "proto": "$VPN_PROTO",
  "subnet": "$VPN_SUBNET/$(netmask_to_prefix "$VPN_NETMASK")",
  "dco": "$DCO_STATE",
  "dco_reason": "$DCO_REASON",
  "cipher": "AES-256-GCM",
  "mssfix": $VPN_MSSFIX,
  "tun_mtu": $VPN_TUN_MTU,
  "dns": ["$VPN_DNS1", "$VPN_DNS2"],
  "max_clients": $VPN_MAX_CLIENTS,
  "redirect_gateway": $([ "$VPN_REDIRECT_GATEWAY" = "1" ] && echo true || echo false)
}
EOF

# OpenVPN status faylini root sifatida 0600 qilib yaratadi va panel uni o'qiy olmaydi.
# Faylni oldindan to'g'ri egalik bilan yaratamiz — openvpn uni O_TRUNC bilan ochgani
# uchun egalik saqlanib qoladi.
touch "$STATE_DIR/openvpn-status.log" "$STATE_DIR/ipp.txt"

chown -R "$PUID:$PGID" "$STATE_DIR" 2>/dev/null || true
chmod 750 "$STATE_DIR"
chmod 640 "$STATE_DIR/ta.key"
chmod 600 "$STATE_DIR/mgmt.pass"
chmod 640 "$STATE_DIR/openvpn-status.log"

# ------------------------------------------------------------------------- NAT
DEFAULT_IF=$(ip route show default | awk '/default/ {print $5; exit}')
PREFIX=$(netmask_to_prefix "$VPN_NETMASK")
VPN_CIDR="$VPN_SUBNET/${PREFIX:-24}"

add_rule() {  # takroriy ishga tushirishda qoidalar ikkilanmasligi uchun
    local table=$1; shift
    iptables -t "$table" -C "$@" 2>/dev/null || iptables -t "$table" -A "$@"
}

add_rule nat POSTROUTING -s "$VPN_CIDR" -o "$DEFAULT_IF" -j MASQUERADE
add_rule filter FORWARD -i tun0 -o "$DEFAULT_IF" -j ACCEPT
add_rule filter FORWARD -i "$DEFAULT_IF" -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT
# Path MTU ga qarab MSS ni moslash — "sayt ochilmayapti / sekin" muammosini yechadi.
add_rule mangle FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

echo "=== OpenVPN ishga tushmoqda ($VPN_PROTO/$VPN_PORT, DCO=$DCO_STATE) ==="

# DCO o'chiq bo'lsa qo'shimcha murakkablik kerak emas.
if [ "$DCO_STATE" != "on" ]; then
    exec openvpn $DCO_FLAG --config "$OVPN_DIR/server.conf"
fi

# DCO yoqilgan: yadro moduli hostda bor, lekin konteyner netns ichida ishlamay
# qolishi mumkin (netlink ruxsatlari, eski docker/seccomp profillari va h.k.).
# Bunda konteyner cheksiz qayta yiqilib turmasin — bir marta sinaymiz va
# muvaffaqiyatsiz bo'lsa DCO'siz davom etamiz. VPN har holda ishlab turadi.
openvpn --config "$OVPN_DIR/server.conf" &
OVPN_PID=$!

# Signallarni bolaga uzatamiz, aks holda `docker stop` 10 soniya kutadi.
trap 'kill -TERM "$OVPN_PID" 2>/dev/null' TERM INT

sleep 6
if kill -0 "$OVPN_PID" 2>/dev/null; then
    wait "$OVPN_PID"
    exit $?
fi

wait "$OVPN_PID" 2>/dev/null
echo "!!! DCO bilan ishga tushib bo'lmadi — DCO'siz qayta urinilmoqda"
echo "=== DCO: o'chiq — konteyner ichida ishlamadi (VPN oddiy rejimda davom etadi) ==="
sed -i 's/"dco": "on"/"dco": "off"/; s/"dco_reason": ""/"dco_reason": "konteyner ichida ishga tushmadi"/' \
    "$STATE_DIR/server_info.json" 2>/dev/null || true
exec openvpn --disable-dco --config "$OVPN_DIR/server.conf"
