#!/usr/bin/env python3
"""VPN panel uchun to'liq tekshiruv to'plami.

Ishga tushirish (konteynerlar ko'tarilgan holda):
    python3 tests/smoke_test.py [http://127.0.0.1:8080]

Parol .env dagi ADMIN_PASS dan olinadi.
"""
from __future__ import annotations

import http.cookiejar
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080").rstrip("/")

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []
SECTION = ""


def section(name: str) -> None:
    global SECTION
    SECTION = name
    print(f"\n\033[1m[{name}]\033[0m")


def check(name: str, cond: bool, detail: str = "") -> bool:
    if cond:
        PASSED.append(f"{SECTION}/{name}")
        print(f"  \033[32mOK\033[0m   {name}")
    else:
        FAILED.append((f"{SECTION}/{name}", detail))
        print(f"  \033[31mFAIL\033[0m {name}" + (f"  -> {detail}" if detail else ""))
    return cond


def admin_password() -> str:
    for line in open(os.path.join(ROOT, ".env")):
        if line.startswith("ADMIN_PASS="):
            return line.split("=", 1)[1].strip()
    raise SystemExit(".env ichida ADMIN_PASS topilmadi")


class Client:
    """Sessiya saqlaydigan oddiy HTTP klient."""

    def __init__(self) -> None:
        self.cj = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cj))

    def raw(self, path: str, data: bytes | None = None, headers: dict | None = None):
        req = urllib.request.Request(BASE + path, data=data, headers=headers or {})
        try:
            r = self.op.open(req)
            return r.getcode(), r.read().decode("utf-8", "replace"), dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace"), dict(e.headers)

    def get(self, path: str) -> str:
        return self.raw(path)[1]

    def token(self, path: str = "/users") -> str:
        m = re.search(r'name="csrf_token" value="([^"]+)"', self.get(path))
        return m.group(1) if m else ""

    def post(self, path: str, fields: dict, src: str = "/users"):
        body = dict(fields)
        body.setdefault("csrf_token", self.token(src))
        return self.raw(path, urllib.parse.urlencode(body).encode())

    def login(self, user: str, pw: str) -> bool:
        code, _, _ = self.post("/login", {"username": user, "password": pw}, src="/login")
        return code in (200, 302) and "Boshqaruv paneli" in self.get("/")


def compose(*args: str) -> str:
    return subprocess.run(["docker", "compose", *args], cwd=ROOT,
                          capture_output=True, text=True).stdout


# ---------------------------------------------------------------- 1. statik
def test_static() -> None:
    section("Statik tekshiruv")
    py = [os.path.join(dp, f) for dp, _, fs in os.walk(ROOT)
          for f in fs if f.endswith(".py") and "__pycache__" not in dp and "/data" not in dp]
    r = subprocess.run([sys.executable, "-m", "py_compile", *py], capture_output=True, text=True)
    check("python sintaksisi", r.returncode == 0, r.stderr[:200])

    for js in ("web/static/app.js", "web/static/theme.js"):
        r = subprocess.run(["node", "--check", os.path.join(ROOT, js)], capture_output=True, text=True)
        check(f"js sintaksisi: {os.path.basename(js)}", r.returncode == 0, r.stderr[:200])

    r = subprocess.run(["sh", "-n", os.path.join(ROOT, "entrypoint.sh")], capture_output=True, text=True)
    check("entrypoint.sh sintaksisi", r.returncode == 0, r.stderr[:200])

    r = subprocess.run(["docker", "compose", "config", "-q"], cwd=ROOT, capture_output=True, text=True)
    check("docker-compose to'g'riligi", r.returncode == 0, r.stderr[:200])

    try:
        import jinja2
        env = jinja2.Environment()
        tdir = os.path.join(ROOT, "web/templates")
        for f in os.listdir(tdir):
            if f.endswith(".html"):
                env.parse(open(os.path.join(tdir, f)).read(), filename=f)
        check("jinja shablonlari", True)
    except ImportError:
        print("  -    jinja2 yo'q, shablon tekshiruvi o'tkazib yuborildi")
    except Exception as e:  # noqa: BLE001
        check("jinja shablonlari", False, str(e)[:200])


# ------------------------------------------------------------ 2. konteyner
def test_containers() -> None:
    section("Konteynerlar")
    # Healthcheck 30 soniyalik intervalda ishlaydi — "starting" holatidan
    # chiqishini kutamiz, aks holda test konteyner aybsiz bo'lsa ham yiqiladi.
    for _ in range(40):
        ps = compose("ps", "--format", "{{.Service}}={{.Status}}")
        if "health: starting" not in ps:
            break
        time.sleep(2)
    ps = compose("ps", "--format", "{{.Service}}={{.Status}}")
    for svc in ("openvpn", "web"):
        line = [l for l in ps.splitlines() if l.startswith(svc + "=")]
        check(f"{svc} ishlayapti", bool(line) and "Up" in line[0], ps[:150])
        check(f"{svc} sog'lom", bool(line) and "healthy" in line[0].lower(), line[0] if line else "")

    code, _, _ = Client().raw("/healthz")
    check("/healthz javob beradi", code == 200, f"kod={code}")


# ------------------------------------------------------- 3. autentifikatsiya
def test_auth() -> None:
    section("Autentifikatsiya")
    anon = Client()
    for path in ("/", "/users", "/activity", "/settings", "/api/status"):
        code, body, _ = anon.raw(path)
        redirected = code == 302 or "Xush kelibsiz" in body
        check(f"login talab qilinadi: {path}", redirected, f"kod={code}")

    bad = Client()
    check("noto'g'ri parol rad etiladi", not bad.login("admin", "butunlay-notogri-parol"))

    c = Client()
    check("to'g'ri parol bilan kirish", c.login("admin", PW))
    return c


# ------------------------------------------------------------ 4. xavfsizlik
def test_security(c: Client) -> None:
    section("Xavfsizlik")
    _, _, headers = c.raw("/")
    want = {
        "Content-Security-Policy": "default-src",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation",
    }
    for key, needle in want.items():
        check(f"sarlavha: {key}", needle in headers.get(key, ""), headers.get(key, "yo'q"))

    cookie = "".join(v for k, v in headers.items() if k.lower() == "set-cookie")
    if not cookie:
        cookie = str([f"{x.name}={x.value}" for x in c.cj])
    raw_cookie = c.raw("/login")[2].get("Set-Cookie", "")
    check("cookie HttpOnly", "HttpOnly" in raw_cookie, raw_cookie[:90])
    check("cookie SameSite", "SameSite" in raw_cookie, raw_cookie[:90])

    # CSRF: token yubormasdan POST
    code, _, _ = c.raw("/users/add", urllib.parse.urlencode(
        {"username": "csrfsiz", "password": "Parol123456x"}).encode())
    check("CSRF tokensiz POST bloklanadi", code in (400, 403), f"kod={code}")

    # CSRF: noto'g'ri token
    code, _, _ = c.raw("/users/add", urllib.parse.urlencode(
        {"username": "csrfyolgon", "password": "Parol123456x", "csrf_token": "yolgon"}).encode())
    check("noto'g'ri CSRF token bloklanadi", code in (400, 403), f"kod={code}")

    # Yo'l bo'ylab chiqish (path traversal)
    for evil in ("../../etc/passwd", "..%2f..%2fetc%2fpasswd", "....//etc/passwd"):
        code, body, _ = c.raw(f"/users/{urllib.parse.quote(evil, safe='')}/config")
        check(f"path traversal to'sildi: {evil[:20]}",
              code in (400, 404, 302) and "root:" not in body, f"kod={code}")

    # XSS / noto'g'ri login nomlari rad etilishi
    for bad_name in ("<script>alert(1)</script>", "a b", "user;rm -rf /", "../x", "a" * 80, ""):
        c.post("/users/add", {"username": bad_name, "password": "Parol123456x"})
        created = os.path.isdir(os.path.join(ROOT, "data/users")) and bad_name in os.listdir(
            os.path.join(ROOT, "data/users"))
        check(f"noto'g'ri login rad etildi: {bad_name[:22]!r}", not created)

    # Zaif parol rad etilishi
    c.post("/users/add", {"username": "zaifparol", "password": "123"})
    users_dir = os.path.join(ROOT, "data/users")
    exists = os.path.isdir(users_dir) and "zaifparol" in os.listdir(users_dir)
    check("zaif parol rad etiladi", not exists)

    # Parol javob sahifasida ochiq ko'rinmasligi
    body = c.get("/settings")
    check("parol HTML ichida ko'rinmaydi", PW not in body)


# ------------------------------------------------------------- 5. sahifalar
def test_pages(c: Client) -> None:
    section("Sahifalar")
    pages = {
        "/": "Boshqaruv paneli",
        "/users": "Foydalanuvchilar",
        "/activity": "Faoliyat",
        "/settings": "Sozlamalar",
    }
    for path, needle in pages.items():
        code, body, _ = c.raw(path)
        check(f"{path} ochiladi", code == 200 and needle in body, f"kod={code}")
        check(f"{path} shablon xatosisiz", "jinja2" not in body.lower()
              and "traceback" not in body.lower())


# ------------------------------------------------------- 6. foydalanuvchilar
def test_users(c: Client) -> None:
    section("Foydalanuvchi amallari")
    name = "testuser_qa"
    users_dir = os.path.join(ROOT, "data/users")
    ovpn = os.path.join(ROOT, "data/ovpn", name + ".ovpn")

    c.post("/users/add", {"username": name, "password": "BirinchiParol1"})
    check("qo'shish", os.path.exists(os.path.join(users_dir, name)))
    check(".ovpn yaratildi", os.path.exists(ovpn))

    conf = open(ovpn).read()
    for needle in ("<ca>", "<tls-auth>", "tun-mtu", "remote ", "data-ciphers", "auth-nocache"):
        check(f".ovpn tarkibi: {needle.strip('<>')}", needle in conf)
    check(".ovpn ichida parol bor", "BirinchiParol1" in conf)

    # takroriy nom
    before = open(os.path.join(users_dir, name)).read()
    c.post("/users/add", {"username": name, "password": "Boshqacha123"})
    check("takroriy login qo'shilmaydi", open(os.path.join(users_dir, name)).read() == before)

    c.post(f"/users/{name}/toggle", {})
    check("bloklash", name in os.listdir(os.path.join(ROOT, "data/state/disabled")))
    c.post(f"/users/{name}/toggle", {})
    check("blokdan chiqarish", name not in os.listdir(os.path.join(ROOT, "data/state/disabled")))

    c.post(f"/users/{name}/password", {"password": "IkkinchiParol2"})
    check("parol yangilash", open(os.path.join(users_dir, name)).read() != before)
    check("parol .ovpn da yangilandi", "IkkinchiParol2" in open(ovpn).read())

    code, _, _ = c.post(f"/users/{name}/disconnect", {})
    check("uzish xatoga olib kelmaydi", code in (200, 302), f"kod={code}")

    code, body, headers = c.raw(f"/users/{name}/config")
    check("config yuklab olish", code == 200 and "<ca>" in body, f"kod={code}")
    check("yuklab olish sarlavhasi", "attachment" in headers.get("Content-Disposition", ""))

    c.post(f"/users/{name}/delete", {})
    check("o'chirish", not os.path.exists(os.path.join(users_dir, name)))
    check(".ovpn ham o'chdi", not os.path.exists(ovpn))


# ------------------------------------------------------------------- 7. API
def test_api(c: Client) -> None:
    section("Jonli API")
    code, body, _ = c.raw("/api/status")
    check("/api/status 200", code == 200, f"kod={code}")
    try:
        data = json.loads(body)
    except json.JSONDecodeError as e:
        check("javob JSON", False, str(e))
        return
    for key in ("clients", "history", "server", "stats", "throughput", "traffic"):
        check(f"kalit: {key}", key in data, f"bor: {list(data)}")
    check("history to'ldirilgan", isinstance(data.get("history"), list) and len(data["history"]) > 0)

    binds = set()
    tdir = os.path.join(ROOT, "web/templates")
    for f in os.listdir(tdir):
        if f.endswith(".html"):
            binds |= set(re.findall(r'data-bind="([^"]+)"', open(os.path.join(tdir, f)).read()))
    for path in sorted(binds):
        node = data
        for part in path.split("."):
            node = node.get(part) if isinstance(node, dict) else None
        check(f"shablon bog'lanishi mavjud: {path}", node is not None)


# --------------------------------------------------------------- 8. janitor
def test_janitor() -> None:
    section("Avtomatik tozalash")
    script = """
import os, time, store, monitor
for u in list(store.list_usernames()):
    if u.startswith("qa_"): monitor._delete_user_files(u)
now, DAY = int(time.time()), 86400
for name, days in {"qa_yangi": 2, "qa_orta": 20, "qa_eski": 32, "qa_juda_eski": 50}.items():
    store.atomic_write(store.user_path(name), "x\\n", mode=0o640)
    store.atomic_write(os.path.join(store.LASTSEEN_DIR, name), str(now - days*DAY), mode=0o640)
r1 = monitor.run_janitor(); r2 = monitor.run_janitor(); r3 = monitor.run_janitor()
left = sorted(u for u in store.list_usernames() if u.startswith("qa_"))
print(__import__("json").dumps({"disable_days": monitor.INACTIVE_DISABLE_DAYS,
    "delete_days": monitor.INACTIVE_DELETE_DAYS, "r1": r1, "r2": r2, "r3": r3, "left": left}))
for u in list(store.list_usernames()):
    if u.startswith("qa_"): monitor._delete_user_files(u)
"""
    r = subprocess.run(["docker", "compose", "exec", "-T", "web", "python", "-"],
                       cwd=ROOT, input=script, capture_output=True, text=True)
    line = [l for l in r.stdout.splitlines() if l.startswith("{")]
    if not check("janitor ishga tushdi", bool(line), r.stderr[-200:]):
        return
    d = json.loads(line[-1])
    check("chegara: 30 kun -> blok", d["disable_days"] == 30, str(d["disable_days"]))
    check("chegara: 45 kun -> o'chirish", d["delete_days"] == 45, str(d["delete_days"]))
    # Fonda ishlaydigan janitor threadi ham bir vaqtda yurishi mumkin, shuning
    # uchun qaysi yurishda bajarilgani emas, YAKUNIY holat tekshiriladi.
    disabled_all = set(d["r1"]["disabled"]) | set(d["r2"]["disabled"]) | set(d["r3"]["disabled"])
    deleted_all = set(d["r1"]["deleted"]) | set(d["r2"]["deleted"]) | set(d["r3"]["deleted"])

    check("32 kunlik bloklandi", "qa_eski" in disabled_all, str(d))
    check("2 kunlik tegilmadi", "qa_yangi" not in disabled_all and "qa_yangi" not in deleted_all)
    check("20 kunlik tegilmadi", "qa_orta" not in disabled_all and "qa_orta" not in deleted_all)
    check("50 kunlik o'chirildi", "qa_juda_eski" in deleted_all or "qa_juda_eski" not in d["left"],
          str(d))
    check("32 kunlik o'chirilmadi", "qa_eski" not in deleted_all, str(d))
    check("faol hisoblar joyida qoldi",
          {"qa_yangi", "qa_orta", "qa_eski"} <= set(d["left"]), str(d["left"]))
    check("idempotent (3-yurish bo'sh)",
          not d["r3"]["disabled"] and not d["r3"]["deleted"], str(d["r3"]))


# --------------------------------------------------------------- 9. VPN
def test_vpn() -> None:
    section("VPN server")
    conf = subprocess.run(["docker", "compose", "exec", "-T", "openvpn",
                           "cat", "/etc/openvpn/server.conf"], cwd=ROOT,
                          capture_output=True, text=True).stdout
    check("server.conf o'qildi", bool(conf.strip()))
    for needle in ("tun-mtu", "mssfix", "data-ciphers", "allow-compression no",
                   "verify-client-cert none", "auth-user-pass-verify", "tls-version-min 1.2"):
        check(f"server.conf: {needle}", needle in conf)

    m = re.search(r"tun-mtu (\d+)", conf)
    check("tun-mtu < 1500 (fragmentatsiyaga qarshi)",
          bool(m) and int(m.group(1)) < 1500, m.group(1) if m else "yo'q")

    mtu = subprocess.run(["docker", "compose", "exec", "-T", "openvpn",
                          "ip", "link", "show", "tun0"], cwd=ROOT,
                         capture_output=True, text=True).stdout
    mm = re.search(r"mtu (\d+)", mtu)
    check("tun0 yadroda to'g'ri MTU bilan", bool(mm) and int(mm.group(1)) < 1500,
          mm.group(1) if mm else "tun0 yo'q")

    ver = subprocess.run(["docker", "compose", "exec", "-T", "openvpn",
                          "openvpn", "--version"], cwd=ROOT,
                         capture_output=True, text=True).stdout
    check("openvpn DCO qo'llab-quvvatlaydi", "[DCO]" in ver, ver.splitlines()[0] if ver else "")

    logs = compose("logs", "openvpn")
    check("ishga tushish yakunlangan", "Initialization Sequence Completed" in logs)
    check("eskirgan opsiya ogohlantirishi yo'q", "DEPRECATED OPTION" not in logs)

    info_path = os.path.join(ROOT, "data/state/server_info.json")
    if os.path.exists(info_path):
        info = json.load(open(info_path))
        for key in ("version", "port", "proto", "subnet", "dco", "cipher", "tun_mtu", "dns"):
            check(f"server_info: {key}", key in info)


# ------------------------------------------------------- 10. mustahkamlik
def test_resilience(c: Client) -> None:
    section("Mustahkamlik")
    name = "qa_persist"
    c.post("/users/add", {"username": name, "password": "SaqlanadiganP1"})
    exists_before = os.path.exists(os.path.join(ROOT, "data/users", name))
    check("test useri yaratildi", exists_before)

    subprocess.run(["docker", "compose", "restart", "web"], cwd=ROOT, capture_output=True)
    for _ in range(30):
        time.sleep(1)
        if Client().raw("/healthz")[0] == 200:
            break
    check("web restartdan keyin ko'tarildi", Client().raw("/healthz")[0] == 200)
    check("foydalanuvchi restartdan keyin saqlandi",
          os.path.exists(os.path.join(ROOT, "data/users", name)))

    c2 = Client()
    check("restartdan keyin login ishlaydi", c2.login("admin", PW))
    c2.post(f"/users/{name}/delete", {})
    check("tozalandi", not os.path.exists(os.path.join(ROOT, "data/users", name)))


# ------------------------------------------------------- 11. rate limiting
def reset_rate_limit() -> None:
    """Login bloklanishini tozalaydi.

    Hisob web jarayonining xotirasida turadi, shuning uchun uni tashqaridan
    tozalab bo'lmaydi — konteynerni qayta ishga tushiramiz. Busiz brute-force
    testi keyingi yurishni 15 daqiqaga bloklab qo'yardi.
    """
    subprocess.run(["docker", "compose", "restart", "web"], cwd=ROOT, capture_output=True)
    for _ in range(40):
        time.sleep(1)
        if Client().raw("/healthz")[0] == 200:
            return


def test_rate_limit() -> None:
    section("Brute-force himoyasi")
    rl = Client()
    codes = []
    for i in range(8):
        code, _, _ = rl.post("/login", {"username": "admin", "password": f"notogri{i}"}, src="/login")
        codes.append(code)
    check("bloklash ishga tushdi (429)", 429 in codes, str(codes))
    check("bloklashgacha kamida 3 urinish", codes.count(401) >= 3, str(codes))

    reset_rate_limit()
    check("blokdan keyin qayta kirish mumkin", Client().login("admin", PW))


def main() -> int:
    global PW
    PW = admin_password()
    print(f"Manzil: {BASE}\nIldiz : {ROOT}")

    test_static()
    test_containers()

    # Oldingi yurishdan qolgan brute-force bloki bo'lsa tozalaymiz.
    if Client().post("/login", {"username": "admin", "password": PW}, src="/login")[0] == 429:
        print("  -    oldingi blok aniqlandi, tozalanmoqda...")
        reset_rate_limit()

    c = test_auth()
    if not c:
        print("\nLogin ishlamadi — qolgan testlar o'tkazib yuborildi")
        return 1
    test_security(c)
    test_pages(c)
    test_users(c)
    test_api(c)
    test_janitor()
    test_vpn()
    test_resilience(c)
    test_rate_limit()

    total = len(PASSED) + len(FAILED)
    print("\n" + "=" * 62)
    print(f"  JAMI: {total} ta tekshiruv | \033[32m{len(PASSED)} o'tdi\033[0m | "
          f"\033[31m{len(FAILED)} yiqildi\033[0m")
    print("=" * 62)
    if FAILED:
        print("\nYiqilganlar:")
        for name, detail in FAILED:
            print(f"  - {name}" + (f"\n      {detail}" if detail else ""))
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
