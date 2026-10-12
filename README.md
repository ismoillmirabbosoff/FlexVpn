# OpenVPN server + boshqaruv paneli

Docker'da ishlaydigan OpenVPN serveri va uni boshqarish uchun web panel.
Klientlar sertifikatsiz, faqat login/parol bilan ulanadi.

```
docker-compose.yml      ikkita servis: openvpn va web
Dockerfile.openvpn      alpine + openvpn + easy-rsa + python3
Dockerfile.web          python:3.12-slim + flask + gunicorn
entrypoint.sh           PKI yaratish, server.conf, NAT, tezlik sozlamalari
scripts/vpnauth.py      parol hashlash (ikkala konteynerda ishlatiladi)
scripts/auth.py         auth-user-pass-verify hooki
scripts/session-hook.py client-connect / client-disconnect hooki
web/                    Flask paneli (app.py, store.py, security.py, monitor.py)
data/config             PKI va server konfiguratsiyasi
data/users              foydalanuvchilar (parol hashlari)
data/state              ulashiladigan holat: status, lastseen, audit, meta
data/ovpn               tayyor .ovpn fayllar
```

## Ishga tushirish

```bash
cp .env.example .env
$EDITOR .env              # kamida SERVER_IP ni to'g'rilang
docker compose up -d --build
docker compose logs web   # boshlang'ich admin paroli shu yerda chiqadi
```

Panel `127.0.0.1:8080` da ochiladi. Tashqariga faqat o'z reverse-proxy'ingiz orqali
chiqaring va HTTPS yoqilgach `.env` da `SECURE_COOKIES=1` qo'ying.

Nginx uchun namuna:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host              $host;
    proxy_set_header X-Real-IP         $remote_addr;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

## Serverda yangilash (git pull)

Har doim shu skript orqali:

```bash
bash deploy.sh
```

U `.env` va butun `data/` ni zaxiraga oladi (`../flexvpn-backups/`), `git pull --ff-only`
qiladi, image'larni yig'adi (xato bo'lsa ishlab turgan konteynerlarga tegmaydi) va faqat
o'zgargan servisni qayta yaratadi. Faqat panel o'zgarsa VPN umuman uzilmaydi; VPN
o'zgarsa klientlar ~5 soniyada o'zi qayta ulanadi (parol so'ralmaydi).

`data/` va `.env` git'da emas — `git pull` ularni hech qachon o'zgartirmaydi va
o'chirmaydi. **`git clean -fdx` ni hech qachon ishlatmang** — u `data/` ni o'chiradi.

Zaxiradan tiklash:

```bash
docker compose down
sudo tar -xzf ../flexvpn-backups/data-YYYYMMDD-HHMMSS.tar.gz
docker compose up -d
```

## Host sozlamasi (bir marta)

```bash
sudo bash scripts/host-tune.sh
docker compose restart openvpn
```

UDP buferlarini kattalashtiradi (yuklama cho'qqisida paket yo'qolmasligi uchun), NAT
jadvalini kengaytiradi va mavjud bo'lsa DCO modulini yuklaydi.

## Panel imkoniyatlari

**Boshqaruv paneli** — jonli o'tkazuvchanlik grafigi (15 daqiqa), ulangan
foydalanuvchilar va ularning real vaqtdagi tezligi, bugungi/umumiy trafik, server
holati (versiya, port, shifr, DNS, DCO), CA sertifikati muddati, so'nggi ulanishlar.
Sahifa har 5 soniyada `/api/status` orqali yangilanadi.

**Foydalanuvchilar** — qo'shish, parolni yangilash, bloklash/blokdan chiqarish,
ulanishni uzish, `.ovpn` yuklab olish, o'chirish. Har bir hisob uchun oxirgi faollik
va avtomatik tozalashgacha qolgan kunlar ko'rsatiladi.

**Faoliyat tarixi** — paneldagi barcha amallar (kim, qachon, qaysi IP dan) va VPN
ulanish jurnali.

**Sozlamalar** — admin parolini almashtirish, xavfsizlik holati, tozalashni qo'lda
ishga tushirish.

Interfeys qora va oq mavzuda ishlaydi; almashtirish tugmasi yon panelning pastida,
tanlov brauzerda saqlanadi.

## Faolsiz foydalanuvchilarni avtomatik tozalash

Har soatda tekshiriladi:

| Holat | Natija |
|---|---|
| 30 kun ulanmagan | hisob bloklanadi, ulanishi uziladi |
| 45 kun ulanmagan | hisob va `.ovpn` fayli butunlay o'chiriladi |

Hozir ulangan foydalanuvchi hech qachon bloklanmaydi. Bloklangan hisobni panelda bir
bosishda qayta faollashtirish mumkin. Muddatlar `INACTIVE_DISABLE_DAYS` va
`INACTIVE_DELETE_DAYS` orqali sozlanadi.

Faollik `data/state/lastseen/<user>` faylidan olinadi — uni OpenVPN'ning
client-connect/disconnect hooklari yozadi. Hech qachon ulanmagan hisoblar uchun
hisobning panelga qo'shilgan sanasi ishlatiladi.

## AmneziaWG (provayder OpenVPN'ni bloklasa)

Ba'zi provayderlar (masalan, Uzbektelekom) OpenVPN'ni UDP'da ham, TCP + tls-crypt'da
ham DPI orqali aniqlab, ulanishdan ~1 daqiqa o'tib trafikni to'xtatadi. Bu server
ichidan qilingan test bilan tasdiqlangan: server to'liq ishlaydi, paketlarni yo'lda
provayder tashlaydi. Bunday tarmoqlar uchun yonma-yon **AmneziaWG** ishlaydi —
WireGuard asosida, trafik belgilari niqoblangan (junk paketlar, tasodifiy
sarlavhalar, QUIC'ga o'xshash signatura).

- Server: `amneziawg` konteyneri, `udp/51443` (`.env`: `AWG_PORT`). Userspace
  (amneziawg-go) — hostga yadro moduli kerak emas.
- Niqoblash parametrlari va server kaliti birinchi ishga tushishda yaratiladi va
  `data/awg/` da saqlanadi. Ularni o'chirmang — aks holda barcha profillar eskiradi.
- Panel: har bir user qatoridagi **AWG** tugmasi `.conf` profilni beradi (kalit va IP
  avtomatik ajratiladi, qayta yuklab olishda o'zgarmaydi).
- Bloklash / o'chirish / 30-45 kunlik tozalash AmneziaWG'ga ham darhol ta'sir qiladi.

Klientda (bir marta, bepul): **AmneziaWG** ilovasi —
Windows: https://github.com/amnezia-vpn/amneziawg-windows-client/releases (eng so'nggi
versiya), Android/iOS: do'konda "AmneziaWG". Ilovada "Import tunnel(s) from file" →
paneldan olingan `.conf` → Activate. Eski versiyalar yangi parametrlarni (S3/S4,
H-oraliqlar, I1) tushunmaydi — har doim eng so'nggisini o'rnating.

## Protokol: TCP 443 + tls-crypt

Provayder DPI'si OpenVPN UDP (1194) trafigini aniqlab, ulanishdan keyin klient
paketlarini tashlab yubormoqda edi (server tomonida tcpdump bilan tasdiqlangan).
Shuning uchun server standart holatda **TCP 443** portida va **tls-crypt** bilan
ishlaydi: port HTTPS bilan bir xil, handshake ham shifrlangan. Klientlarga yangi
ilova kerak emas — OpenVPN Connect'ning o'zi, faqat paneldan yangi `.ovpn` yuklab
olinadi (eski profillar yuklab olishda avtomatik yangilanadi, ichidagi parol saqlanadi).

Host'da 443/tcp port bo'sh bo'lishi shart (`ss -ltnp | grep ':443 '`).

## Tezlik va barqarorlik

- **Parol tekshiruvi tez** — PBKDF2 faqat yangi ulanishda bir marta bajariladi; TCP
  rejimida bu qisqa kutish paket yo'qotmaydi. (Fonda/deferred tekshiruv TCP serverda
  ulanishni 20-60 soniyaga cho'zgani uchun olib tashlandi.)
- **auth-token** — birinchi kirishdan keyin klient token oladi. Soatlik qayta kalit
  almashish va qayta ulanishlar parolsiz, bir zumda o'tadi. Token kaliti diskda —
  server restartidan keyin ham ishlaydi. Bloklangan, o'chirilgan yoki paroli
  almashtirilgan user eski tokeni bilan kira olmaydi.
- **explicit-exit-notify** — server to'xtaganda klientlarga RESTART yuboradi, ular 60
  soniya kutmasdan darhol qayta ulanadi. Panelning "uzish" tugmasi ham shunday ishlaydi.
- **DCO** — hostda `ovpn` yadro moduli (Linux 6.16+) bo'lsa avtomatik yoqiladi; shifrlash
  yadro ichida bajariladi. Eski `ovpn_dco_v2` moduli OpenVPN 2.7 bilan ishlamaydi.
- **TCP MSS** — iptables ikkala yo'nalishda MSS ni `VPN_MSSFIX - 64` ga tushiradi (DCO
  rejimida ham). Fragmentatsiya va katta paketlarning yo'qolishi oldi olinadi.
- **UDP buferlari** — server 4 MB so'raydi (`VPN_SOCK_BUF`); hostda
  `scripts/host-tune.sh` chegarani ko'taradi.
- **Siqish o'chirilgan**, shifr `AES-256-GCM` (zaxira: `CHACHA20-POLY1305`).
- **Barqaror image** — `alpine:3.24` (OpenVPN 2.7.x); `edge` emas.
- **Docker loglari aylantiriladi** — disk to'lib qolmaydi.

Server tarmoq interfeysining MTU si 1500 dan kichik bo'lsa: `VPN_TUN_MTU = MTU - 60`,
`VPN_MSSFIX = MTU - 100` (masalan MTU 1400 -> 1340 / 1300). `scripts/host-tune.sh` va
`deploy.sh` buni avtomatik tekshirib, kerakli qiymatni ko'rsatadi.

## Xavfsizlik

- **Parollar hashlangan** — pbkdf2-sha256, 210 000 iteratsiya. Eski ochiq matnli
  parollar birinchi ishga tushishda avtomatik hashga o'tkaziladi; foydalanuvchilar
  mavjud `.ovpn` fayllari bilan ulanaveradi.
- **Path traversal yopilgan** — barcha username'lar qat'iy shablon bo'yicha
  tekshiriladi va fayl yo'llari bitta joyda shakllanadi.
- **CSRF** — barcha o'zgartiruvchi so'rovlar token bilan himoyalangan.
- **Brute-force** — 15 daqiqada 5 ta noto'g'ri urinishdan keyin IP bloklanadi.
- **Sessiya** — HttpOnly, SameSite=Strict, HTTPS ortida Secure; 1 soat harakatsizlikdan
  keyin tugaydi.
- **HTTP sarlavhalari** — CSP (tashqi resurslarsiz), HSTS, X-Frame-Options: DENY,
  X-Content-Type-Options, Referrer-Policy.
- **Zaif boshlang'ich parol** — panel almashtirilmaguncha boshqa bo'limlarni ochmaydi.
- **Server maxfiy kaliti** web konteynerga umuman berilmaydi: unga faqat `ca.crt` va
  `ta.key` nusxalanadi.
- **Audit log** — har bir amal `data/state/audit.jsonl` ga yoziladi.

### Nima himoyalanmagan

`.ovpn` fayllar ichida login va parol ochiq yoziladi — bu ularni bir marta bosib
ulanadigan qilish uchun ataylab shunday. Fayl tarqalsa hisob ham tarqaydi. Parol
hashlangani uchun yo'qolgan `.ovpn` ni parol bilan qayta yaratib bo'lmaydi: panel uni
parolsiz yaratadi (klient ulanganda so'raydi) yoki parolni yangilash orqali yangi
to'liq fayl olinadi.

## Foydali buyruqlar

```bash
docker compose logs -f openvpn        # VPN jurnali, auth urinishlari
docker compose logs -f web            # panel jurnali
docker compose restart openvpn        # konfiguratsiyani qayta o'qish
cat data/state/openvpn-status.log     # jonli status (har 5 sekundda)
tail -f data/state/auth.log           # kirish urinishlari
```
