#!/bin/bash
set -e

OVPN_DIR="/etc/openvpn"
PKI_DIR="$OVPN_DIR/pki"
STATE_DIR="$OVPN_DIR/state"
SCRIPTS_DIR="/opt/vpn-scripts"
EASYRSA="/usr/share/easy-rsa/easyrsa"

VPN_SUBNET="${VPN_SUBNET:-10.8.0.0}"
VPN_NETMASK="${VPN_NETMASK:-255.255.255.0}"
# Standart: TCP 443 + tls-crypt. Provayder DPI'si OpenVPN UDP trafigini aniqlab,
# ulanishdan keyin klient paketlarini tashlab yubormoqda edi. 443/tcp — HTTPS
# porti, tls-crypt esa handshake'ni ham shifrlab, OpenVPN belgilarini yashiradi.
VPN_PORT="${VPN_PORT:-443}"
VPN_PROTO="${VPN_PROTO:-tcp}"
VPN_DNS1="${VPN_DNS1:-1.1.1.1}"
VPN_DNS2="${VPN_DNS2:-8.8.8.8}"
# /24 tarmoqda 252 ta manzil bor. duplicate-cn yoqilganda har bir qurilma alohida
# o'rin egallaydi — 100 lik chegara ofisda tez to'lib, yangi ulanishlar rad etilardi.
VPN_MAX_CLIENTS="${VPN_MAX_CLIENTS:-250}"
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
VPN_DCO="${VPN_DCO:-0}"

# Web konteyner shu uid/gid bilan ishlaydi. State katalogi o'sha egaga beriladi,
# shunda ikkala konteyner ham bir xil fayllar bilan ishlay oladi.
PUID="${PUID:-1000}"
PGID="${PGID:-1000}"

case "$VPN_PROTO" in
    udp|udp4) VPN_PROTO=udp ;;
    tcp|tcp4|tcp-server) VPN_PROTO=tcp ;;
    *) echo "XATO: VPN_PROTO=$VPN_PROTO (udp yoki tcp bo'lishi kerak)"; exit 1 ;;
esac

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

# tls-crypt kaliti: control kanalni (handshake'ni ham) shifrlaydi va
# imzolaydi — DPI OpenVPN'ni ochiq ko'rinadigan handshake orqali taniy olmaydi,
# kalitsiz kelgan har qanday paketga server umuman javob bermaydi.
if [ ! -s "$OVPN_DIR/tc.key" ]; then
    openvpn --genkey tls-crypt "$OVPN_DIR/tc.key"
fi
chmod 600 "$OVPN_DIR/tc.key"

# auth-gen-token HMAC kaliti. Diskda saqlangani uchun server qayta ishga tushganda
# ham klientlarning tokenlari amal qiladi va ular parolsiz, bir zumda qayta ulanadi.
if [ ! -s "$OVPN_DIR/auth-token.key" ]; then
    openvpn --genkey auth-token "$OVPN_DIR/auth-token.key"
fi
chmod 600 "$OVPN_DIR/auth-token.key"

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
elif [ -d /sys/module/ovpn ]; then
    DCO_FLAG=""
    DCO_STATE="on"
elif [ -d /sys/module/ovpn_dco_v2 ]; then
    # OpenVPN 2.7 faqat yangi "ovpn" modulini (Linux 6.16+ yoki ovpn-backports)
    # tushunadi. Eski ovpn-dco-v2 bilan DCO yoqilgandek ko'rinib, aslida ishlamasdi.
    DCO_REASON="hostda eski ovpn_dco_v2 moduli bor, OpenVPN 2.7 ga yangi 'ovpn' moduli kerak (Linux 6.16+ yoki ovpn-backports)"
else
    DCO_REASON="hostda ovpn yadro moduli yuklanmagan -> hostda bajaring: sudo modprobe ovpn"
fi

if [ "$DCO_STATE" = "on" ]; then
    echo "=== DCO: YOQILGAN (shifrlash yadro darajasida) ==="
else
    echo "=== DCO: o'chiq — $DCO_REASON ==="
    [ "$VPN_DCO" = "1" ] && echo "!!! VPN_DCO=1 so'ralgan edi, lekin yoqib bo'lmadi"
fi

# UDP soket buferlari. OS standarti (~208 KB) yuklama cho'qqisida to'lib qoladi va
# kernel paketlarni jimgina tashlaydi — bu VPN'dagi "packet loss" ning eng ko'p
# uchraydigan sababi. Qiymat hostdagi net.core.rmem_max/wmem_max bilan
# cheklanadi, shuning uchun hostda scripts/host-tune.sh ni bir marta bajaring.
VPN_SOCK_BUF="${VPN_SOCK_BUF:-4194304}"

TUNING=""
if [ "$DCO_STATE" = "off" ]; then
    # DCO yoqilganda navbat uzunligini yadro boshqaradi.
    TUNING="txqueuelen 1000"
fi

REDIRECT_LINE=""
if [ "$VPN_REDIRECT_GATEWAY" = "1" ]; then
    REDIRECT_LINE='push "redirect-gateway def1 bypass-dhcp"'
fi

DUPLICATE_LINE=""
if [ "$VPN_DUPLICATE_CN" = "1" ]; then
    DUPLICATE_LINE="duplicate-cn"
fi

if [ "$VPN_PROTO" = "udp" ]; then
    # Server to'xtaganda (yangilash, restart) klientlarga RESTART yuboriladi va
    # ular 60 soniya ping-restart kutmasdan, darhol qayta ulanadi. Faqat UDP:
    # TCP da ulanish uzilishini klient o'zi darhol sezadi.
    PROTO_OPTS="explicit-exit-notify 1"
else
    # Kichik paketlar (SSH, RDP, VoIP) Nagle algoritmida kutib qolmasin.
    PROTO_OPTS='tcp-nodelay'
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
tls-crypt $OVPN_DIR/tc.key
tls-version-min 1.2

topology subnet
server $VPN_SUBNET $VPN_NETMASK
ifconfig-pool-persist $STATE_DIR/ipp.txt 0

$REDIRECT_LINE
push "dhcp-option DNS $VPN_DNS1"
push "dhcp-option DNS $VPN_DNS2"

# --- o'tkazuvchanlik ---------------------------------------------------------
sndbuf $VPN_SOCK_BUF
rcvbuf $VPN_SOCK_BUF
push "sndbuf 0"
push "rcvbuf 0"
$TUNING
# Fragmentatsiya tezlikni eng ko'p yeydigan omil — MSS ni oldindan cheklaymiz.
tun-mtu $VPN_TUN_MTU
mssfix $VPN_MSSFIX
# 2.6+ klientlar MTU ni serverdan oladi; eskilari uchun bir xil qiymat .ovpn
# faylining o'ziga ham yoziladi, shunda ikki tomon kelishmovchiligi bo'lmaydi.
push "tun-mtu $VPN_TUN_MTU"
# Siqish VORACLE hujumiga yo'l ochadi va zamonaviy trafikda foyda bermaydi.
allow-compression no

$PROTO_OPTS

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

# Muvaffaqiyatli kirishdan keyin klientga token beriladi va soatlik qayta kalit
# almashish hamda qayta ulanishlar parolsiz o'tadi. external-auth: token bo'lsa
# ham auth.py chaqiriladi — bloklangan/o'chirilgan/paroli almashgan user tokeni
# bilan qaytib kira olmaydi. Kalit diskda: server restartidan keyin ham amal qiladi.
auth-gen-token 0 43200 external-auth
auth-gen-token-secret $OVPN_DIR/auth-token.key
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
cp -f "$OVPN_DIR/tc.key" "$STATE_DIR/tc.key"
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
chmod 640 "$STATE_DIR/tc.key"
rm -f "$STATE_DIR/ta.key"
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
add_rule filter FORWARD -i "$DEFAULT_IF" -o tun0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# TCP MSS ni ikkala yo'nalishda ham aniq qiymatga tushiramiz. --clamp-mss-to-pmtu
# klient -> internet SYN paketida chiquvchi interfeys MTU sini (1500) oladi va
# hech narsani kamaytirmaydi; DCO rejimida esa openvpn'ning mssfix'i umuman
# ishlamaydi. Natijada katta paketlar fragmentlanib, yo'lda yo'qolardi.
# mssfix = shifrlangan UDP yuklamasi; undan AEAD qo'shimchasi (24) va
# IP+TCP sarlavhalari (40) ayriladi.
TCP_MSS="${VPN_TCP_MSS:-$(( VPN_MSSFIX - 64 ))}"
for dir in -i -o; do
    add_rule mangle FORWARD "$dir" tun0 -p tcp --tcp-flags SYN,RST SYN \
        -m tcpmss --mss "$(( TCP_MSS + 1 )):65535" -j TCPMSS --set-mss "$TCP_MSS"
done

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

# Signallarni bolaga uzatamiz va u tugashini kutamiz: openvpn klientlarga
# RESTART (explicit-exit-notify) yuborib ulgurishi kerak.
trap 'kill -TERM "$OVPN_PID" 2>/dev/null; wait "$OVPN_PID" 2>/dev/null; exit 0' TERM INT

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
