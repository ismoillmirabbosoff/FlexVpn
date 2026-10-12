#!/usr/bin/env bash
# Serverda xavfsiz yangilash.
#
#   bash deploy.sh
#
# Nima qiladi:
#   1. .env va butun data/ katalogini (userlar, PKI, holat) zaxiraga oladi.
#   2. git pull --ff-only (mahalliy o'zgarishlar ustidan hech narsa yozilmaydi).
#   3. Image'larni yig'adi. Xato bo'lsa — ishlab turgan konteynerlarga TEGILMAYDI.
#   4. `docker compose up -d` — faqat haqiqatan o'zgargan servis qayta yaratiladi.
#      Faqat panel o'zgargan bo'lsa VPN umuman uzilmaydi. VPN o'zgargan bo'lsa,
#      klientlar bir necha soniyada o'zi qayta ulanadi (explicit-exit-notify +
#      auth-token).
#   5. Ikkala servis sog'lomligini tekshiradi.
#
# data/ va .env git'da emas: git pull ularni hech qachon o'zgartirmaydi.
set -euo pipefail

cd "$(dirname "$(readlink -f "$0")")"

BACKUP_DIR="${BACKUP_DIR:-$(pwd)/../flexvpn-backups}"
KEEP_BACKUPS="${KEEP_BACKUPS:-14}"
TS="$(date +%Y%m%d-%H%M%S)"

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
die() { printf '\n\033[31mXATO: %s\033[0m\n' "$*" >&2; exit 1; }

[ -f .env ] || die ".env topilmadi. Namunadan nusxa oling: cp .env.example .env"
command -v docker >/dev/null || die "docker topilmadi"

# ------------------------------------------------------------------- MTU
# Shifrlangan paket = VPN_TUN_MTU + 52 bayt. Host MTU sidan oshsa paketlar
# bo'linadi va yo'qoladi — eng ko'p uchraydigan "nestabil VPN" sababi.
IFACE="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')"
HOST_MTU="$(cat "/sys/class/net/${IFACE:-eth0}/mtu" 2>/dev/null || echo 1500)"
TUN_MTU="$(grep -E '^VPN_TUN_MTU=' .env | tail -1 | cut -d= -f2 | tr -d ' "')"
TUN_MTU="${TUN_MTU:-1420}"
PROTO="$(grep -E '^VPN_PROTO=' .env | tail -1 | cut -d= -f2 | tr -d ' "')"
# TCP rejimida tashqi paketlarni TCP o'zi bo'ladi — bu tekshiruv faqat UDP uchun.
if [ "${PROTO:-tcp}" = "udp" ] && [ $(( TUN_MTU + 52 )) -gt "$HOST_MTU" ]; then
    printf '\n\033[31m!!! VPN_TUN_MTU=%s server MTU (%s) uchun juda katta.\033[0m\n' "$TUN_MTU" "$HOST_MTU"
    printf '    .env da qo'"'"'ying: VPN_TUN_MTU=%s  VPN_MSSFIX=%s\n' $(( HOST_MTU - 60 )) $(( HOST_MTU - 100 ))
fi

# ------------------------------------------------------------------- zaxira
say "Zaxira: $BACKUP_DIR"
mkdir -p "$BACKUP_DIR"
BACKUP_DIR="$(cd "$BACKUP_DIR" && pwd)"
cp -p .env "$BACKUP_DIR/env-$TS"

if [ -d data ]; then
    # data/ ichidagi PKI kalitlari root'ga tegishli (600) — oddiy user o'qiy
    # olmaydi. Shuning uchun arxivni konteyner ichida root nomidan yaratamiz.
    docker run --rm \
        -v "$(pwd)/data:/src/data:ro" \
        -v "$BACKUP_DIR:/backup" \
        alpine:3.24 \
        tar -czf "/backup/data-$TS.tar.gz" -C /src data \
        || die "data/ zaxirasi yaratilmadi — yangilash to'xtatildi"
    echo "data zaxirasi: $BACKUP_DIR/data-$TS.tar.gz"
fi

# Eski zaxiralarni tozalash (oxirgi $KEEP_BACKUPS tasi qoladi).
for pattern in 'data-*.tar.gz' 'env-*'; do
    # shellcheck disable=SC2012
    ls -1t "$BACKUP_DIR"/$pattern 2>/dev/null | tail -n +"$((KEEP_BACKUPS + 1))" \
        | xargs -r rm -f --
done

# ---------------------------------------------------------------- git pull
say "git pull"
ENV_BACKUP="$BACKUP_DIR/env-$TS"
restore_env() {
    # Bir martalik o'tish: .env ilgari git'da edi. Uni git'dan chiqargan
    # commit pull qilinganda git faylni o'chirib yuboradi — darhol tiklaymiz.
    if [ ! -f .env ]; then
        cp -p "$ENV_BACKUP" .env
        echo ".env zaxiradan tiklandi"
    fi
}
trap restore_env EXIT

if git ls-files --error-unmatch .env >/dev/null 2>&1; then
    # .env hali kuzatilmoqda va serverda o'zgartirilgan bo'lsa pull rad etiladi.
    # Nusxa yuqorida olindi; git'dagi holatga qaytarib, pull'dan keyin tiklaymiz.
    git checkout -- .env
    git pull --ff-only
    cp -p "$ENV_BACKUP" .env
else
    git pull --ff-only
fi
restore_env

# ------------------------------------------------------------------ build
say "Image'lar yig'ilmoqda (ishlab turgan VPN'ga ta'sir qilmaydi)"
docker compose build || die "build muvaffaqiyatsiz — ishlab turgan konteynerlar o'zgartirilmadi"

# ------------------------------------------------------------------- up
say "O'zgargan servislar yangilanmoqda"
docker compose up -d

# ---------------------------------------------------------------- tekshiruv
say "Sog'liq tekshiruvi"
ok=0
# openvpn status faylini har 5 soniyada yangilaydi — u yangi bo'lsa server ishlayapti.
vpn_alive() {
    docker exec openvpn-server sh -c \
        'test $(( $(date +%s) - $(stat -c %Y /etc/openvpn/state/openvpn-status.log) )) -lt 30' \
        2>/dev/null
}
for _ in $(seq 1 60); do
    web=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' vpn-web-panel 2>/dev/null || echo none)
    if vpn_alive && [ "$web" = "healthy" ]; then
        ok=1
        break
    fi
    sleep 2
done

docker compose ps
if [ "$ok" != 1 ]; then
    docker compose logs --tail 40 openvpn
    die "servislar sog'lom holatga kelmadi. Zaxira: $BACKUP_DIR/data-$TS.tar.gz"
fi
docker logs openvpn-server 2>&1 | grep -E "=== DCO" | tail -1 || true
say "Tayyor"
