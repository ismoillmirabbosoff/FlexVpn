"""OpenVPN boshqaruv paneli."""

from __future__ import annotations

import os
import time

from flask import (
    Flask,
    abort,
    flash,
    g,
    has_request_context,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from flask.sessions import SecureCookieSessionInterface
from werkzeug.middleware.proxy_fix import ProxyFix

import monitor
import store
import security
from vpnauth import hash_password, is_hashed, password_problem, valid_username

SERVER_IP = (os.environ.get("SERVER_IP") or "").strip()
VPN_PORT = os.environ.get("VPN_PORT", "1194")
VPN_PROTO = os.environ.get("VPN_PROTO", "udp")
# Klient .ovpn fayliga yoziladi — entrypoint.sh dagi server qiymati bilan
# bir xil bo'lishi shart (ikkalasi ham compose'dan bitta manbadan oladi).
VPN_TUN_MTU = os.environ.get("VPN_TUN_MTU", "1420")
VPN_MSSFIX = os.environ.get("VPN_MSSFIX", "1360")

# .ovpn shabloni o'zgarganda bu qatorni yangilang. Har bir yaratilgan faylning
# birinchi qatoriga yoziladi va yuklab olishda tekshiriladi — eski shablon bilan
# yaratilgan fayllar avtomatik qayta generatsiya qilinadi. Aks holda mavjud
# foydalanuvchilar MTU kabi tuzatishlarni umuman olmay qoladi.
# Server manzili ham izga kiradi: SERVER_IP o'zgarganda eski profillar eski
# manzil bilan qolib ketmasin (klient butunlay boshqa serverga ulanmasin).
OVPN_TEMPLATE_MARK = (
    f"vpnpanel-profile v3 remote={SERVER_IP or '-'}:{VPN_PORT}/{VPN_PROTO} "
    f"mtu={VPN_TUN_MTU} mss={VPN_MSSFIX}"
)
SECURE_COOKIES = (os.environ.get("SECURE_COOKIES") or "auto").lower()
TRUST_PROXY = int(os.environ.get("TRUST_PROXY", "1"))
SESSION_IDLE_TIMEOUT = int(os.environ.get("SESSION_IDLE_TIMEOUT", "3600"))

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
PUBLIC_ENDPOINTS = {"login", "healthz", "static"}


class DynamicSessionInterface(SecureCookieSessionInterface):
    """Cookie'ning Secure bayrog'ini so'rov protokoliga qarab qo'yadi.

    Shunda HTTPS ortida cookie himoyalanadi, lokal HTTP testda esa kirish buzilmaydi.
    """

    def get_cookie_secure(self, app):
        if SECURE_COOKIES in {"1", "true", "yes"}:
            return True
        if SECURE_COOKIES in {"0", "false", "no"}:
            return False
        return has_request_context() and request.is_secure


app = Flask(__name__)
app.secret_key = security.load_secret_key()
app.session_interface = DynamicSessionInterface()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_NAME="vpnpanel",
    PERMANENT_SESSION_LIFETIME=SESSION_IDLE_TIMEOUT,
    MAX_CONTENT_LENGTH=64 * 1024,
    JSON_SORT_KEYS=False,
    # Statik fayllar URL'ida versiya bo'lgani uchun uzoq muddat keshlanadi.
    SEND_FILE_MAX_AGE_DEFAULT=31536000,
)


def _asset_version() -> str:
    """Statik fayllarning eng so'nggi o'zgarish vaqti — kesh buzuvchi belgi.

    Yangi versiya tarqatilganda brauzer eski CSS/JS ni ushlab qolmaydi.
    """
    latest = 0.0
    static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
    for root, _dirs, files in os.walk(static_dir):
        for name in files:
            try:
                latest = max(latest, os.path.getmtime(os.path.join(root, name)))
            except OSError:
                continue
    return str(int(latest))


ASSET_V = _asset_version()
if TRUST_PROXY > 0:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=TRUST_PROXY, x_proto=TRUST_PROXY, x_host=TRUST_PROXY)


# ------------------------------------------------------------------ middleware


@app.before_request
def guard():
    endpoint = request.endpoint or ""

    if request.method not in SAFE_METHODS and endpoint not in {"login", "static"}:
        if not security.csrf_ok(session, request.form.get("csrf_token")):
            abort(400, "CSRF tokeni noto'g'ri — sahifani yangilab, qaytadan urinib ko'ring.")

    if endpoint in PUBLIC_ENDPOINTS:
        return None

    if not session.get("logged_in"):
        return redirect(url_for("login", next=request.path if request.method == "GET" else None))

    # Harakatsizlik bo'yicha sessiya muddati.
    now = int(time.time())
    if now - session.get("seen", now) > SESSION_IDLE_TIMEOUT:
        session.clear()
        flash("Sessiya muddati tugadi, qaytadan kiring", "error")
        return redirect(url_for("login"))
    session["seen"] = now

    # Zaif boshlang'ich parol almashtirilmaguncha boshqa sahifalarga o'tkazmaymiz.
    if security.load_admin().get("must_change") and endpoint not in {"settings", "change_password", "logout"}:
        flash("Davom etishdan oldin admin parolini almashtiring", "error")
        return redirect(url_for("settings"))

    return None


@app.after_request
def finish(response):
    return security.apply_headers(response, https=request.is_secure)


@app.context_processor
def inject():
    return {
        "csrf_token": security.issue_csrf(session),
        "now": int(time.time()),
        "server_ip_set": bool(SERVER_IP),
        "vpn_online": monitor.server_online(),
        "asset_v": ASSET_V,
    }


# --------------------------------------------------------------- shablon filtrlari


def _num(value) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


@app.template_filter("fbytes")
def fbytes(value) -> str:
    size = _num(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if size >= 100 or unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


@app.template_filter("fbits")
def fbits(value) -> str:
    rate = _num(value)
    if rate < 1:
        return "0 bit/s"
    for unit in ("bit/s", "Kbit/s", "Mbit/s", "Gbit/s"):
        if rate < 1000 or unit == "Gbit/s":
            return f"{rate:.0f} {unit}" if rate >= 100 or unit == "bit/s" else f"{rate:.1f} {unit}"
        rate /= 1000
    return f"{rate:.1f} Gbit/s"


@app.template_filter("dur")
def dur(value) -> str:
    seconds = int(max(0, _num(value)))
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes = rest // 60
    if days:
        return f"{days} kun {hours} soat"
    if hours:
        return f"{hours} soat {minutes} daq"
    if minutes:
        return f"{minutes} daq"
    return f"{seconds} soniya"


@app.template_filter("ago")
def ago(value) -> str:
    ts = int(_num(value))
    if not ts:
        return "—"
    delta = int(time.time()) - ts
    if delta < 60:
        return "hozirgina"
    if delta < 3600:
        return f"{delta // 60} daqiqa oldin"
    if delta < 86400:
        return f"{delta // 3600} soat oldin"
    if delta < 30 * 86400:
        return f"{delta // 86400} kun oldin"
    return time.strftime("%d.%m.%Y", time.localtime(ts))


@app.template_filter("dt")
def dt(value) -> str:
    ts = int(_num(value))
    return time.strftime("%d.%m.%Y", time.localtime(ts)) if ts else "—"


ACTION_LABELS = {
    "login": "Panelga kirdi",
    "login_failed": "Kirish urinishi muvaffaqiyatsiz",
    "logout": "Paneldan chiqdi",
    "user_add": "Foydalanuvchi qo'shildi",
    "user_delete": "Foydalanuvchi o'chirildi",
    "user_disable": "Foydalanuvchi bloklandi",
    "user_enable": "Foydalanuvchi faollashtirildi",
    "user_disconnect": "Ulanish uzildi",
    "user_password_reset": "Parol yangilandi",
    "config_download": "Konfiguratsiya yuklab olindi",
    "admin_password_change": "Admin paroli almashtirildi",
    "auto_disable": "Faolsizlik uchun avtomatik bloklandi",
    "auto_delete": "Faolsizlik uchun avtomatik o'chirildi",
    "janitor_manual": "Tozalash qo'lda ishga tushirildi",
    "password_hashed": "Parol hashga o'tkazildi",
}


@app.template_filter("action_label")
def action_label(value) -> str:
    return ACTION_LABELS.get(str(value), str(value))


def client_ip() -> str:
    return request.remote_addr or "-"


def audit(action: str, target: str = "", detail: str = "") -> None:
    store.audit(action, actor=session.get("admin_user", "admin"), target=target, detail=detail, ip=client_ip())


def require_user(username: str) -> str:
    """Username'ni tekshiradi va mavjudligiga ishonch hosil qiladi.

    Bu yagona joy orqali barcha yo'llar shakllanadi — shuning uchun `../` kabi
    qiymatlar hech qachon fayl yo'liga tushmaydi.
    """
    if not valid_username(username) or not os.path.isfile(store.user_path(username)):
        abort(404)
    return username


# ------------------------------------------------------------------------ auth


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        key = client_ip()
        blocked = security.login_blocked(key)
        if blocked:
            flash(f"Juda ko'p urinish. {blocked // 60 + 1} daqiqadan keyin qayta urinib ko'ring.", "error")
            return render_template("login.html"), 429

        username = request.form.get("username", "")
        password = request.form.get("password", "")

        if security.check_admin(username, password):
            security.record_login_success(key)
            session.clear()
            session.permanent = True
            session["logged_in"] = True
            session["admin_user"] = username
            session["seen"] = int(time.time())
            security.issue_csrf(session)
            store.audit("login", actor=username, ip=key)
            nxt = request.args.get("next", "")
            return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("dashboard"))

        left = security.record_login_failure(key)
        store.audit("login_failed", actor=username or "-", ip=key)
        if left:
            flash(f"Login yoki parol noto'g'ri. Qolgan urinishlar: {left}", "error")
        else:
            flash("Juda ko'p urinish. Hisob 15 daqiqaga bloklandi.", "error")
        return render_template("login.html"), 401

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    store.audit("logout", actor=session.get("admin_user", "admin"), ip=client_ip())
    session.clear()
    return redirect(url_for("login"))


# ------------------------------------------------------------------- sahifalar


@app.route("/")
def dashboard():
    users = _user_rows()
    clients = monitor.live_clients()
    info = monitor.server_info()

    return render_template(
        "dashboard.html",
        clients=clients,
        history=monitor.throughput_history(),
        throughput=monitor.current_throughput(),
        traffic=monitor.traffic_summary(),
        info=info,
        ca=monitor.ca_expiry(),
        users=users,
        stats={
            "online": len(clients),
            "total": len(users),
            "blocked": sum(1 for u in users if u["activity"]["disabled"]),
            "expiring": sum(
                1 for u in users
                if not u["activity"]["disabled"] and u["activity"]["days_to_disable"] <= 7
            ),
        },
        sessions=store.recent_sessions(12),
        server_ip=SERVER_IP,
        disable_days=monitor.INACTIVE_DISABLE_DAYS,
        delete_days=monitor.INACTIVE_DELETE_DAYS,
    )


@app.route("/users")
def users_page():
    return render_template(
        "users.html",
        users=_user_rows(),
        disable_days=monitor.INACTIVE_DISABLE_DAYS,
        delete_days=monitor.INACTIVE_DELETE_DAYS,
    )


@app.route("/activity")
def activity():
    return render_template(
        "activity.html",
        audit_events=store.recent_audit(150),
        sessions=store.recent_sessions(80),
    )


@app.route("/settings")
def settings():
    return render_template(
        "settings.html",
        admin=security.load_admin(),
        info=monitor.server_info(),
        ca=monitor.ca_expiry(),
        server_ip=SERVER_IP,
        disable_days=monitor.INACTIVE_DISABLE_DAYS,
        delete_days=monitor.INACTIVE_DELETE_DAYS,
        secure_cookies=SECURE_COOKIES,
        https=request.is_secure,
    )


# ------------------------------------------------------------------- amallar


@app.route("/users/add", methods=["POST"])
def add_user():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not valid_username(username):
        flash("Username 3-32 belgi, harf/raqam bilan boshlanib tugashi kerak (. _ - ishlatsa bo'ladi)", "error")
        return redirect(url_for("users_page"))

    problem = password_problem(password)
    if problem:
        flash(problem, "error")
        return redirect(url_for("users_page"))

    if os.path.exists(store.user_path(username)):
        flash(f"'{username}' allaqachon mavjud", "error")
        return redirect(url_for("users_page"))

    store.ensure_dirs()
    store.atomic_write(store.user_path(username), hash_password(password), mode=0o640)
    store.update_meta(username, created=int(time.time()))
    _generate_ovpn(username, password)
    audit("user_add", target=username)
    flash(f"'{username}' qo'shildi — konfiguratsiyani hoziroq yuklab oling", "success")
    return redirect(url_for("users_page"))


@app.route("/users/<username>/password", methods=["POST"])
def reset_password(username):
    username = require_user(username)
    password = request.form.get("password", "")

    problem = password_problem(password)
    if problem:
        flash(problem, "error")
        return redirect(url_for("users_page"))

    store.atomic_write(store.user_path(username), hash_password(password), mode=0o640)
    _generate_ovpn(username, password)
    monitor.disconnect_client(username)  # eski parol bilan ochilgan sessiya yopilsin
    audit("user_password_reset", target=username)
    flash(f"'{username}' paroli yangilandi va yangi konfiguratsiya tayyorlandi", "success")
    return redirect(url_for("users_page"))


@app.route("/users/<username>/toggle", methods=["POST"])
def toggle_user(username):
    username = require_user(username)
    if store.is_disabled(username):
        store.set_disabled(username, False)
        audit("user_enable", target=username)
        flash(f"'{username}' qayta faollashtirildi", "success")
    else:
        store.set_disabled(username, True, "admin tomonidan bloklandi")
        monitor.disconnect_client(username)
        audit("user_disable", target=username)
        flash(f"'{username}' bloklandi", "success")
    return redirect(request.referrer or url_for("users_page"))


@app.route("/users/<username>/disconnect", methods=["POST"])
def disconnect_user(username):
    username = require_user(username)
    ok, message = monitor.disconnect_client(username)
    audit("user_disconnect", target=username, detail=message)
    flash(f"'{username}': {message}", "success" if ok else "error")
    return redirect(request.referrer or url_for("dashboard"))


@app.route("/users/<username>/delete", methods=["POST"])
def delete_user(username):
    username = require_user(username)
    monitor.disconnect_client(username)
    monitor._delete_user_files(username)
    audit("user_delete", target=username)
    flash(f"'{username}' o'chirildi", "success")
    return redirect(url_for("users_page"))


@app.route("/users/<username>/config")
def download_config(username):
    username = require_user(username)
    path = store.ovpn_path(username)

    if not os.path.exists(path):
        # Parol hash holida saqlanadi, uni qayta tiklab bo'lmaydi. Shuning uchun
        # yo'qolgan konfiguratsiya login/parolsiz yaratiladi — klient so'raydi.
        _generate_ovpn(username, password=None)
        flash(
            f"'{username}' uchun konfiguratsiya qaytadan yaratildi. Parol ichiga "
            "yozilmadi — klient ulanganda so'raydi. Parolni ichiga yozish uchun "
            "parolni yangilang.",
            "error",
        )
    elif not _ovpn_is_current(path):
        # Eski shablon: MTU/shifr sozlamalari yangilangan. Ichidagi login-parolni
        # saqlab qolib, faqat sozlama qatorlarini yangilaymiz.
        _regenerate_keeping_credentials(username, path)
        flash(f"'{username}' konfiguratsiyasi yangi sozlamalar bilan yangilandi.", "ok")

    if not os.path.exists(path):
        flash("Server sertifikatlari hali tayyor emas. Bir oz kuting.", "error")
        return redirect(url_for("users_page"))

    audit("config_download", target=username)
    return send_file(
        path,
        as_attachment=True,
        download_name=f"{username}.ovpn",
        mimetype="application/x-openvpn-profile",
    )


@app.route("/settings/password", methods=["POST"])
def change_password():
    current = request.form.get("current_password", "")
    new = request.form.get("new_password", "")
    confirm = request.form.get("confirm_password", "")

    admin = security.load_admin()
    if not security.check_admin(admin["username"], current):
        flash("Joriy parol noto'g'ri", "error")
        return redirect(url_for("settings"))
    if new != confirm:
        flash("Yangi parollar mos kelmadi", "error")
        return redirect(url_for("settings"))
    problem = password_problem(new)
    if problem:
        flash(problem, "error")
        return redirect(url_for("settings"))

    security.set_admin_password(new)
    audit("admin_password_change")
    flash("Admin paroli yangilandi", "success")
    return redirect(url_for("settings"))


@app.route("/settings/cleanup", methods=["POST"])
def run_cleanup():
    result = monitor.run_janitor()
    audit("janitor_manual", detail=str(result))
    if result["disabled"] or result["deleted"]:
        flash(
            f"Bloklandi: {len(result['disabled'])} ta, o'chirildi: {len(result['deleted'])} ta",
            "success",
        )
    else:
        flash("Tozalash uchun faolsiz foydalanuvchi topilmadi", "success")
    return redirect(url_for("settings"))


# ----------------------------------------------------------------------- API


@app.route("/api/status")
def api_status():
    clients = monitor.live_clients()
    users = _user_rows()
    return jsonify({
        "server": monitor.server_info(),
        "throughput": monitor.current_throughput(),
        "history": monitor.throughput_history(),
        "traffic": monitor.traffic_summary(),
        "clients": clients,
        "stats": {
            "online": len(clients),
            "total": len(users),
            "blocked": sum(1 for u in users if u["activity"]["disabled"]),
        },
    })


@app.route("/healthz")
def healthz():
    return jsonify({"ok": True, "vpn": monitor.server_online()})


# ------------------------------------------------------------------- yordamchi


def _user_rows() -> list[dict]:
    rows = []
    for username in store.list_usernames():
        rows.append({
            "username": username,
            "activity": monitor.user_activity(username),
            "has_config": os.path.exists(store.ovpn_path(username)),
        })
    return rows


def _ovpn_is_current(path: str) -> bool:
    """Fayl amaldagi shablon bilan yaratilganmi."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return OVPN_TEMPLATE_MARK in handle.readline()
    except OSError:
        return False


def _regenerate_keeping_credentials(username: str, path: str) -> None:
    """Eski .ovpn ichidagi <auth-user-pass> blokini saqlab, qolganini yangilaydi."""
    password = None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
        start = text.find("<auth-user-pass>")
        end = text.find("</auth-user-pass>")
        if start != -1 and end != -1:
            lines = [ln.strip() for ln in text[start + 16:end].splitlines() if ln.strip()]
            if len(lines) >= 2:
                password = lines[1]
    except OSError:
        pass
    _generate_ovpn(username, password)


def _generate_ovpn(username: str, password: str | None) -> None:
    ca_cert = store.read_text(store.CA_FILE)
    ta_key = store.read_text(store.TA_FILE)
    if not ca_cert or not ta_key:
        return

    remote = SERVER_IP or "SERVER-IP-KIRITILMAGAN"
    embedded = ""
    if password is not None:
        embedded = f"\n<auth-user-pass>\n{username}\n{password}\n</auth-user-pass>\n"

    config = f"""# {OVPN_TEMPLATE_MARK}
client
dev tun
proto {VPN_PROTO}
remote {remote} {VPN_PORT}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
auth SHA256
tls-version-min 1.2
auth-user-pass
auth-nocache
key-direction 1
# Tezlik uchun: fragmentatsiyani oldini olamiz va bufferlarni OS ga qoldiramiz.
# tun-mtu server bilan bir xil bo'lishi shart, aks holda katta paketlar yo'qoladi.
tun-mtu {VPN_TUN_MTU}
mssfix {VPN_MSSFIX}
sndbuf 0
rcvbuf 0
verb 3

<ca>
{ca_cert.strip()}
</ca>

<tls-auth>
{ta_key.strip()}
</tls-auth>
{embedded}"""

    os.makedirs(store.OVPN_DIR, exist_ok=True)
    store.atomic_write(store.ovpn_path(username), config, mode=0o640)


def _migrate_legacy_users() -> None:
    """Ochiq matnda saqlangan eski parollarni hashga o'tkazadi.

    Mavjud .ovpn fayllar ichidagi login/parol o'zgarmagani uchun foydalanuvchilar
    hech narsani sezmaydi — ular eski konfiguratsiyasi bilan ulanaveradi.
    """
    now = int(time.time())
    for username in store.list_usernames():
        path = store.user_path(username)
        record = store.read_text(path).strip()
        if record and not is_hashed(record):
            store.atomic_write(path, hash_password(record), mode=0o640)
            store.audit("password_hashed", target=username, detail="ochiq matndan pbkdf2 ga o'tkazildi")

        meta = store.get_meta(username)
        if not meta.get("created"):
            # Avval ro'yxatga olinmagan hisoblarga to'liq muddat beriladi, aks holda
            # birinchi ishga tushishdayoq ommaviy bloklash sodir bo'lishi mumkin edi.
            store.update_meta(username, created=now, imported=True)


def bootstrap() -> None:
    store.ensure_dirs()
    try:
        store.check_writable()
    except RuntimeError as exc:
        print("\n" + "=" * 66 + f"\n  ISHGA TUSHIB BO'LMADI\n\n{exc}" + "=" * 66 + "\n", flush=True)
        raise
    security.load_admin()
    # .env dagi ADMIN_PASS o'zgargan bo'lsa qo'llanadi (panel orqali qo'yilgan
    # parol saqlanib qoladi — faqat env qiymatining o'zi o'zgarsa yoziladi).
    synced = security.sync_admin_from_env()
    if synced:
        print(f"admin: {synced}", flush=True)
    _migrate_legacy_users()
    monitor.start_background()
    if not SERVER_IP:
        print("DIQQAT: SERVER_IP o'rnatilmagan — .ovpn fayllarda server manzili bo'lmaydi", flush=True)


bootstrap()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
