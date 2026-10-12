#!/usr/bin/env bash
# Host (server) yadrosini VPN uchun sozlash. Bir marta bajariladi:
#
#   sudo bash scripts/host-tune.sh
#
# Sozlamalar /etc/sysctl.d/99-flexvpn.conf ga yoziladi va reboot'dan keyin ham
# saqlanadi. Ishlab turgan VPN'ni uzmaydi — qiymatlar darhol qo'llanadi,
# soket buferi esa openvpn keyingi safar ishga tushganda kattalashadi.
set -euo pipefail

[ "$(id -u)" = 0 ] || { echo "root sifatida ishga tushiring: sudo bash $0"; exit 1; }

CONF=/etc/sysctl.d/99-flexvpn.conf

cat > "$CONF" <<'EOF'
# FlexVPN — paket yo'qolishining oldini olish.

# UDP soket buferlari. Standart 208 KB yuklama cho'qqisida to'lib qoladi va yadro
# VPN paketlarini jimgina tashlaydi. openvpn 4 MB so'raydi (VPN_SOCK_BUF), lekin
# yadro uni shu chegaragacha qisqartiradi.
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576

# Tarmoq kartasidan kelgan paketlar navbati — trafik cho'qqisida to'lib qolmasin.
net.core.netdev_max_backlog = 16384

# NAT jadvali. To'lsa yadro "nf_conntrack: table full, dropping packet" deb
# BARCHA yangi ulanishlarni tashlaydi — userlarda sayt ochilmay qoladi.
net.netfilter.nf_conntrack_max = 524288
net.netfilter.nf_conntrack_udp_timeout_stream = 180

# Docker va VPN uchun forwarding.
net.ipv4.ip_forward = 1

# Tezroq va barqarorroq TCP (host'ning o'z ulanishlari: panel, docker pull).
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_mtu_probing = 1
EOF

modprobe nf_conntrack 2>/dev/null || true
modprobe tcp_bbr 2>/dev/null || true

# Har bir qatorni alohida qo'llaymiz: yadroda biror kalit bo'lmasa, qolganlari
# baribir qo'llansin.
grep -E '^[a-z]' "$CONF" | while IFS='=' read -r key value; do
    key="$(echo "$key" | xargs)"; value="$(echo "$value" | xargs)"
    if sysctl -q -w "$key=$value" >/dev/null 2>&1; then
        printf '  OK    %s = %s\n' "$key" "$value"
    else
        printf '  SKIP  %s (bu yadroda mavjud emas)\n' "$key"
    fi
done

# Hashsize conntrack_max ga mos bo'lsin (aks holda qidiruv sekinlashadi).
if [ -w /sys/module/nf_conntrack/parameters/hashsize ]; then
    echo 131072 > /sys/module/nf_conntrack/parameters/hashsize || true
fi

# DCO: Linux 6.16+ da shifrlash yadro ichida — tezlik bir necha barobar oshadi.
if modprobe ovpn 2>/dev/null; then
    echo ovpn > /etc/modules-load.d/flexvpn-ovpn.conf
    echo "  OK    ovpn (DCO) moduli yuklandi — 'docker compose restart openvpn' dan keyin yoqiladi"
else
    echo "  INFO  ovpn (DCO) moduli yo'q (yadro $(uname -r)). VPN DCO'siz ham to'liq ishlaydi."
fi

echo
echo "Tayyor. Asosiy interfeys MTU si: $(ip -o link show "$(ip route show default | awk '/default/ {print $5; exit}')" | grep -o 'mtu [0-9]*')"
echo "Agar 1500 dan kichik bo'lsa (masalan 1450), .env da VPN_TUN_MTU ni 1370, VPN_MSSFIX ni 1310 qiling."
