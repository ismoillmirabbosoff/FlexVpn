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

## Tezlik

VPN yoqilganda tezlik tushmasligi uchun qilinganlar:

- **DCO (Data Channel Offload)** — hostda `ovpn` yadro moduli bo'lsa avtomatik
  yoqiladi. Shifrlash yadro ichida bajarilib, foydalanuvchi makoniga nusxalash
  yo'qoladi. Bu eng katta ta'sir ko'rsatuvchi omil. Holati panelda ko'rinadi.
- **MSS clamping** — `mssfix 1360` va iptables `--clamp-mss-to-pmtu`. Fragmentatsiya
  tezlikni eng ko'p yeydigan sabab; bu ikkisi uni oldini oladi.
- **Buferlar OS ixtiyorida** — `sndbuf 0` / `rcvbuf 0` serverda ham, klientda ham.
  OpenVPN'ning 64 KB standart buferi tezlikni sun'iy ravishda cheklaydi.
- **`fast-io`** va `txqueuelen 1000` — UDP uchun syscall sonini kamaytiradi.
- **Siqish o'chirilgan** (`allow-compression no`) — foyda bermaydi, VORACLE hujumiga
  yo'l ochadi.
- **Shifrlar** — `AES-256-GCM` (AES-NI bo'lgan protsessorlarda tez), telefonlar uchun
  `CHACHA20-POLY1305` zaxira sifatida.
- **DNS** — Cloudflare `1.1.1.1` birinchi o'rinda, kechikishni kamaytiradi.

DCO ni hostda yoqish (Linux 6.x, ovpn-dco-dkms paketi):

```bash
sudo apt install ovpn-dco-dkms   # yoki distributivingizdagi paket
sudo modprobe ovpn_dco_v2
docker compose restart openvpn
```

Modul topilmasa DCO avtomatik o'chadi va server odatdagidek ishlayveradi.

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
