from urllib.parse import quote
from email.message import EmailMessage
import smtplib
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta

from flask import (
    Blueprint,
    Response,
    abort,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
)
from flask_login import current_user, login_required, login_user, logout_user
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from ldap3 import Connection, Server
from radius_eap_mschapv2_client.client import EAPMSCHAPv2Client

from .models import User, db

auth_bp = Blueprint("auth", __name__)
_suggest_rate_lock = threading.Lock()
_suggest_rate_windows = defaultdict(deque)

# Cache semplice per i suggerimenti LDAP: {query: (lista_suggerimenti, timestamp_scadenza)}
_ldap_suggest_cache = {}
_ldap_cache_lock = threading.Lock()
_LDAP_CACHE_TTL_SECONDS = 300  # 5 minuti


def _safe_next_url() -> str:
    next_url = request.args.get("next") or request.form.get("next")
    if next_url and next_url.startswith("/"):
        return next_url
    return "/"


def _is_cnr_email(email: str) -> bool:
    return email.lower().endswith("@cnr.it")


def _validate_strong_password(password: str) -> tuple[bool, str]:
    if len(password) < 8:
        return False, "La password deve contenere almeno 8 caratteri."
    if not any(c.isdigit() for c in password):
        return False, "La password deve contenere almeno un numero."
    if not any(not c.isalnum() for c in password):
        return False, "La password deve contenere almeno un carattere speciale."
    return True, ""


def _ldap_username_from_identifier(identifier: str) -> str:
    value = (identifier or "").strip()
    # Supporta input tipo DOMINIO\utente
    if "\\" in value:
        value = value.split("\\", 1)[1]
    # Forza autenticazione LDAP senza dominio email
    if "@" in value:
        return value.split("@", 1)[0]
    return value


def _public_login_url(next_url: str | None = None) -> str:
    path = current_app.config.get("PUBLIC_LOGIN_PATH", "/auth/login")
    if next_url:
        return f"{path}?next={quote(next_url)}"
    return path


def _public_register_url() -> str:
    return current_app.config.get("PUBLIC_REGISTER_PATH", "/auth/register")


def _public_admin_users_url() -> str:
    return current_app.config.get("PUBLIC_ADMIN_USERS_PATH", "/auth/admin/users")


def _public_admin_hba_sso_url() -> str:
    return current_app.config.get("PUBLIC_ADMIN_HBA_SSO_PATH", "/auth/admin/hba-sso")


def _public_suggest_url() -> str:
    return current_app.config.get("PUBLIC_SUGGEST_PATH", "/auth/suggest-users")


def _hba_sso_serializer() -> URLSafeTimedSerializer:
    secret = current_app.config.get("HBA_SSO_SECRET") or current_app.config["SECRET_KEY"]
    return URLSafeTimedSerializer(secret)


def _ldap_lookup_and_bind(username: str, password: str):
    cfg = current_app.config
    if not cfg["LDAP_ENABLED"] or not cfg["LDAP_SERVER_URI"] or not password:
        return None

    # Rimosso get_info=ALL per velocizzare la connessione (handshake immediato)
    server = Server(cfg["LDAP_SERVER_URI"], use_ssl=cfg["LDAP_USE_SSL"])
    user_dn = None
    user_attrs = {}

    if cfg["LDAP_USER_DN_TEMPLATE"]:
        user_dn = cfg["LDAP_USER_DN_TEMPLATE"].format(username=username)
    else:
        if not cfg["LDAP_BASE_DN"]:
            return None

        bind_dn = cfg["LDAP_BIND_DN"] or None
        bind_password = cfg["LDAP_BIND_PASSWORD"] or None
        with Connection(
            server, user=bind_dn, password=bind_password, auto_bind=True
        ) as search_conn:
            search_ok = search_conn.search(
                search_base=cfg["LDAP_BASE_DN"],
                search_filter=cfg["LDAP_SEARCH_FILTER"].format(username=username),
                attributes=["mail", "cn", "uid"],
                size_limit=1,
            )
            if not search_ok or not search_conn.entries:
                return None
            entry = search_conn.entries[0]
            user_dn = entry.entry_dn
            user_attrs = entry.entry_attributes_as_dict

    if not user_dn:
        return None

    try:
        with Connection(server, user=user_dn, password=password, auto_bind=True):
            mail_list = user_attrs.get("mail", [])
            cn_list = user_attrs.get("cn", [])
            mail = mail_list[0] if mail_list else ""
            full_name = cn_list[0] if cn_list else username
            return {"username": username, "email": mail, "full_name": full_name}
    except Exception:
        return None


def _radius_authenticate(username: str, password: str):
    cfg = current_app.config
    if not cfg.get("RADIUS_ENABLED") or not password:
        return None

    try:
        # La libreria gestisce internamente lo scambio EAP-MSCHAPv2
        client = EAPMSCHAPv2Client(
            server=cfg["RADIUS_SERVER"],
            shared_secret=cfg["RADIUS_SECRET"],
            username=username,
            password=password,
            port=cfg.get("RADIUS_PORT", 1812),
            timeout=cfg.get("RADIUS_TIMEOUT", 5),
            nas_identifier=cfg.get("RADIUS_NAS_ID", "SSO-Gateway"),
            nas_ip_address=cfg.get("RADIUS_NAS_IP", "127.0.0.1"),
        )

        if client.authenticate():
            # In eduroam l'email è spesso lo username stesso (es. utente@ente.it)
            email = username if "@" in username else f"{username}@radius.local"
            return {"username": username, "email": email}
    except Exception as e:
        current_app.logger.error(f"Errore RADIUS/eduroam per {username}: {e}")

    return None


def _rate_limit_allow(ip: str, per_min: int) -> bool:
    if per_min <= 0:
        return True

    now = time.monotonic()
    window = 60.0
    with _suggest_rate_lock:
        q = _suggest_rate_windows[ip]
        while q and (now - q[0]) > window:
            q.popleft()
        if len(q) >= per_min:
            return False
        q.append(now)
    return True


def _client_ip() -> str:
    remote_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "-")
    return remote_ip.split(",")[0].strip()


def _ldap_suggest(query: str) -> list[str]:
    cfg = current_app.config
    if not cfg.get("LDAP_ENABLED") or not cfg.get("LOGIN_SUGGEST_LDAP_ENABLED"):
        return []
    if not cfg.get("LDAP_SERVER_URI") or not cfg.get("LDAP_BASE_DN"):
        return []

    # Controllo cache
    now = datetime.now()
    with _ldap_cache_lock:
        if query in _ldap_suggest_cache:
            suggestions, expiry = _ldap_suggest_cache[query]
            if now < expiry:
                return suggestions
            else:
                del _ldap_suggest_cache[query]

    # Connessione ottimizzata senza get_info=ALL
    server = Server(cfg["LDAP_SERVER_URI"], use_ssl=cfg["LDAP_USE_SSL"])
    bind_dn = cfg["LDAP_BIND_DN"] or None
    bind_password = cfg["LDAP_BIND_PASSWORD"] or None

    suggestions = []
    try:
        with Connection(
            server, user=bind_dn, password=bind_password, auto_bind=True
        ) as conn:
            conn.search(
                search_base=cfg["LDAP_BASE_DN"],
                search_filter=cfg["LDAP_SUGGEST_FILTER"].format(query=query),
                attributes=["uid"],
                size_limit=20, # Limitiamo per performance
            )
            for entry in conn.entries:
                data = entry.entry_attributes_as_dict
                values = data.get("uid", [])
                if values:
                    val = str(values[0]).strip().lower()
                    if val:
                        suggestions.append(val)
        
        # Salvataggio in cache
        with _ldap_cache_lock:
            expiry = now + timedelta(seconds=_LDAP_CACHE_TTL_SECONDS)
            _ldap_suggest_cache[query] = (suggestions, expiry)
            # Pulizia automatica se la cache diventa troppo grande (> 500 entry)
            if len(_ldap_suggest_cache) > 500:
                _ldap_suggest_cache.clear()

    except Exception:
        current_app.logger.exception("Errore suggerimenti LDAP")
        return []

    return suggestions


def _authenticate_local(identifier: str, password: str):
    ident = (identifier or "").strip().lower()
    if not ident:
        return None

    user = User.query.filter(
        (User.username == ident) | (User.email == ident)
    ).first()
    if not user or not user.check_password(password):
        return None
    if user.source == "local":
        if not user.active:
            return "disabled"
        if not user.email_confirmed:
            return "email_unconfirmed"
        if not user.approved:
            return "pending"
    return user


def _upsert_ldap_user(ldap_profile: dict):
    username = ldap_profile["username"]
    email = ldap_profile.get("email") or f"{username}@ldap.local"

    user = User.query.filter_by(username=username).first()
    if user:
        user.email = email
        user.source = "ldap"
        user.approved = True
        user.email_confirmed = True
    else:
        user = User(
            username=username,
            email=email,
            source="ldap",
            password_hash=None,
            approved=True,
            email_confirmed=True,
        )
        db.session.add(user)
    db.session.commit()
    return user


def _upsert_radius_user(radius_profile: dict):
    username = radius_profile["username"]
    email = radius_profile.get("email") or f"{username}@radius.local"

    user = User.query.filter_by(username=username).first()
    if user:
        user.email = email
        user.source = "radius"
        user.approved = True
        user.email_confirmed = True
    else:
        user = User(
            username=username,
            email=email,
            source="radius",
            password_hash=None,
            approved=True,
            email_confirmed=True,
        )
        db.session.add(user)
    db.session.commit()
    return user


def _email_serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"])


def _build_public_url(path: str) -> str:
    base = current_app.config.get("APP_BASE_URL", "").rstrip("/")
    if base:
        return f"{base}{path}"
    return request.url_root.rstrip("/") + path


def _build_confirm_link(token: str) -> str:
    prefix = current_app.config.get(
        "PUBLIC_CONFIRM_EMAIL_PREFIX", "/auth/confirm-email"
    ).rstrip("/")
    path = f"{prefix}/{quote(token)}"
    return _build_public_url(path)


def _send_email(subject: str, recipient: str, body: str) -> bool:
    cfg = current_app.config
    if not cfg["MAIL_ENABLED"] or not recipient:
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg["MAIL_FROM"]
    msg["To"] = recipient
    msg.set_content(body)

    try:
        with smtplib.SMTP(cfg["MAIL_HOST"], cfg["MAIL_PORT"], timeout=10) as smtp:
            if cfg["MAIL_USE_TLS"]:
                smtp.starttls()
            if cfg["MAIL_USERNAME"]:
                smtp.login(cfg["MAIL_USERNAME"], cfg["MAIL_PASSWORD"])
            smtp.send_message(msg)
        return True
    except Exception as exc:
        current_app.logger.exception("Invio email fallito: %s", exc)
        return False


def _send_registration_emails(user: User):
    token = _email_serializer().dumps({"user_id": user.id, "email": user.email})
    confirm_link = _build_confirm_link(token)

    user_body = (
        "Ciao,\n\n"
        "abbiamo ricevuto la tua registrazione. Per confermare la tua email clicca questo link:\n"
        f"{confirm_link}\n\n"
        "Dopo la conferma, l'account restera' in attesa di approvazione da parte di un amministratore.\n"
    )
    _send_email("Conferma email registrazione", user.email, user_body)


def _parse_recipients(raw: str) -> list[str]:
    return [item.strip() for item in (raw or "").split(",") if item.strip()]


def _send_admin_new_registration_notice(user: User):
    admin_emails = _parse_recipients(current_app.config.get("ADMIN_NOTIFY_EMAIL", ""))
    if admin_emails:
        admin_body = (
            "Nuova registrazione locale ricevuta:\n"
            f"- Username: {user.username}\n"
            f"- Email: {user.email}\n"
            f"- ID: {user.id}\n\n"
            "L'utente ha confermato l'email e puo' essere approvato dal pannello admin.\n"
        )
        for admin_email in admin_emails:
            _send_email("Nuova registrazione utente", admin_email, admin_body)


def _admin_required():
    original_uri = request.headers.get("X-Original-URI", request.path)
    if not current_user.is_authenticated:
        return redirect(_public_login_url(original_uri))
    if not current_user.is_admin:
        logout_user()
        flash("Accesso protetto. Effettua il login con l'account amministrativo.")
        return redirect(_public_login_url(original_uri))
    return None


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    force_login = request.args.get("confirmed") == "1"
    if current_user.is_authenticated and not force_login:
        return redirect(_safe_next_url())

    if request.method == "POST":
        login_per_min = max(1, int(current_app.config.get("LOGIN_RATE_LIMIT_PER_MIN", 30)))
        if not _rate_limit_allow(f"login:{_client_ip()}", login_per_min):
            flash("Troppi tentativi di login. Attendi un minuto e riprova.")
            return (
                render_template(
                    "login.html",
                    next_url=_safe_next_url(),
                    register_url=_public_register_url(),
                    suggest_url=_public_suggest_url(),
                    suggest_enabled=current_app.config.get("LOGIN_SUGGEST_ENABLED", False),
                    suggest_min_chars=current_app.config.get("LOGIN_SUGGEST_MIN_CHARS", 3),
                ),
                429,
            )

        identifier = request.form.get("identifier", "").strip() or request.form.get(
            "username", ""
        ).strip()
        password = request.form.get("password", "")
        ldap_username = _ldap_username_from_identifier(identifier)

        ldap_profile = _ldap_lookup_and_bind(ldap_username, password)
        if ldap_profile:
            user = _upsert_ldap_user(ldap_profile)
            login_user(user)
            return redirect(_safe_next_url())

        # 2. RADIUS / eduroam (EAP-MSCHAPv2)
        radius_profile = _radius_authenticate(identifier, password)
        if radius_profile:
            user = _upsert_radius_user(radius_profile)
            login_user(user)
            return redirect(_safe_next_url())

        # 3. Autenticazione locale (SQLite)
        local_auth = _authenticate_local(identifier, password)
        if local_auth == "disabled":
            flash("Account disabilitato. Contatta l'amministratore.")
            return render_template(
                "login.html",
                next_url=_safe_next_url(),
                register_url=_public_register_url(),
                suggest_url=_public_suggest_url(),
                suggest_enabled=current_app.config.get("LOGIN_SUGGEST_ENABLED", False),
                suggest_min_chars=current_app.config.get("LOGIN_SUGGEST_MIN_CHARS", 3),
            )

        if local_auth == "email_unconfirmed":
            flash("Email non confermata. Controlla la casella di posta.")
            return render_template(
                "login.html",
                next_url=_safe_next_url(),
                register_url=_public_register_url(),
                suggest_url=_public_suggest_url(),
                suggest_enabled=current_app.config.get("LOGIN_SUGGEST_ENABLED", False),
                suggest_min_chars=current_app.config.get("LOGIN_SUGGEST_MIN_CHARS", 3),
            )

        if local_auth == "pending":
            flash("Account locale in attesa di approvazione da parte dell'amministratore.")
            return render_template(
                "login.html",
                next_url=_safe_next_url(),
                register_url=_public_register_url(),
                suggest_url=_public_suggest_url(),
                suggest_enabled=current_app.config.get("LOGIN_SUGGEST_ENABLED", False),
                suggest_min_chars=current_app.config.get("LOGIN_SUGGEST_MIN_CHARS", 3),
            )

        if local_auth:
            user = local_auth
            login_user(user)
            return redirect(_safe_next_url())

        flash("Credenziali non valide.")

    return render_template(
        "login.html",
        next_url=_safe_next_url(),
        register_url=_public_register_url(),
        suggest_url=_public_suggest_url(),
        suggest_enabled=current_app.config.get("LOGIN_SUGGEST_ENABLED", False),
        suggest_min_chars=current_app.config.get("LOGIN_SUGGEST_MIN_CHARS", 3),
    )


@auth_bp.route("/suggest-users", methods=["GET"])
def suggest_users():
    if not current_app.config.get("LOGIN_SUGGEST_ENABLED", False):
        return jsonify({"suggestions": []})

    min_chars = max(1, int(current_app.config.get("LOGIN_SUGGEST_MIN_CHARS", 3)))
    per_min = max(1, int(current_app.config.get("LOGIN_SUGGEST_RATE_LIMIT_PER_MIN", 120)))
    client_ip = _client_ip()
    if not _rate_limit_allow(client_ip, per_min):
        return jsonify({"suggestions": [], "error": "rate_limit"}), 429

    q = (request.args.get("q", "") or "").strip().lower()
    if len(q) < min_chars:
        return jsonify({"suggestions": []})

    users = (
        User.query.filter_by(source="local", active=True)
        .filter((User.email.ilike(f"%{q}%")) | (User.username.ilike(f"%{q}%")))
        .order_by(User.email.asc())
        .all()
    )

    local = [u.email for u in users]
    ldap = [v.split("@", 1)[0] for v in _ldap_suggest(q)]

    merged = []
    seen = set()
    for value in local + ldap:
        if value and value not in seen:
            seen.add(value)
            merged.append(value)

    return jsonify({"suggestions": merged})


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        username = email

        if not email or not password:
            flash("Compila tutti i campi.")
            return render_template("register.html", login_url=_public_login_url())

        if not _is_cnr_email(email):
            flash("Registrazione consentita solo con email @cnr.it.")
            return render_template("register.html", login_url=_public_login_url())

        is_ok, reason = _validate_strong_password(password)
        if not is_ok:
            flash(reason)
            return render_template("register.html", login_url=_public_login_url())

        if password != confirm_password:
            flash("Le password non coincidono.")
            return render_template("register.html", login_url=_public_login_url())

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash("Username o email gia' presenti.")
            return render_template("register.html", login_url=_public_login_url())

        user = User(
            username=username,
            email=email,
            source="local",
            approved=False,
            email_confirmed=False,
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        _send_registration_emails(user)
        flash("Registrazione inviata all'amministratore. Controlla la tua casella email per confermarla.")
        return redirect(_public_login_url())

    return render_template("register.html", login_url=_public_login_url())


@auth_bp.route("/confirm-email/<token>", methods=["GET"])
def confirm_email(token: str):
    try:
        data = _email_serializer().loads(
            token, max_age=current_app.config["EMAIL_CONFIRM_MAX_AGE_SECONDS"]
        )
    except SignatureExpired:
        flash("Link di conferma scaduto. Richiedi una nuova registrazione.")
        return redirect(_public_login_url())
    except BadSignature:
        flash("Link di conferma non valido.")
        return redirect(_public_login_url())

    user = User.query.filter_by(id=data.get("user_id"), email=data.get("email")).first()
    if not user:
        flash("Utente non trovato per questo link.")
        return redirect(_public_login_url())

    if not user.email_confirmed:
        user.email_confirmed = True
        db.session.commit()
        _send_admin_new_registration_notice(user)

    flash("Email confermata. Ora attendi l'approvazione dell'amministratore.")
    return redirect(f"{_public_login_url()}?confirmed=1")


@auth_bp.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    return redirect(_public_login_url())


@auth_bp.route("/check", methods=["GET"])
def check():
    if not current_user.is_authenticated:
        login_url = _public_login_url(request.headers.get("X-Original-URI", "/"))
        return Response("Unauthorized", 401, headers={"X-Auth-Redirect": login_url})

    return Response(
        "OK",
        200,
        headers={
            "X-Authenticated-User": current_user.username,
            "X-Authenticated-Email": current_user.email,
        },
    )


@auth_bp.route("/me", methods=["GET"])
@login_required
def me():
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "source": current_user.source,
        "approved": current_user.approved,
        "email_confirmed": current_user.email_confirmed,
        "is_admin": current_user.is_admin,
    }


@auth_bp.route("/admin/users", methods=["GET"])
def admin_users():
    guard = _admin_required()
    if guard:
        return guard

    pending_users = (
        User.query.filter_by(source="local", approved=False).order_by(User.id.asc()).all()
    )
    local_users = (
        User.query.filter_by(source="local", approved=True).order_by(User.id.asc()).all()
    )
    return render_template(
        "admin_users.html",
        pending_users=pending_users,
        local_users=local_users,
        admin_action_base=_public_admin_users_url().rstrip("/"),
        backup_admin_url=_public_admin_hba_sso_url(),
        logout_url=current_app.config.get("PUBLIC_LOGOUT_PATH", "/auth/logout"),
    )


@auth_bp.route("/admin/hba-sso", methods=["GET"])
def admin_hba_sso():
    guard = _admin_required()
    if guard:
        return guard

    if not current_app.config.get("HBA_SSO_ENABLED", True):
        flash("Accesso SSO a Backup/Restore disabilitato.")
        return redirect(_public_admin_users_url())

    payload = {
        "is_admin": True,
        "email": current_user.email,
        "username": current_user.username,
    }
    token = _hba_sso_serializer().dumps(payload)
    hba_sso_url = current_app.config.get("HBA_SSO_URL", "/hba/sso-login")
    separator = "&" if "?" in hba_sso_url else "?"
    return redirect(f"{hba_sso_url}{separator}token={quote(token)}")


@auth_bp.route("/admin/users/create", methods=["POST"])
def create_user_admin():
    guard = _admin_required()
    if guard:
        return guard

    email = (request.form.get("email", "") or "").strip().lower()
    password = request.form.get("password", "") or ""
    note = (request.form.get("note", "") or "").strip()

    if not email or not password:
        flash("Email e password sono obbligatorie per creare l'utente.")
        return redirect(_public_admin_users_url())

    ok, reason = _validate_strong_password(password)
    if not ok:
        flash(reason)
        return redirect(_public_admin_users_url())

    existing = User.query.filter((User.username == email) | (User.email == email)).first()
    if existing:
        flash("Utente gia' presente.")
        return redirect(_public_admin_users_url())

    user = User(
        username=email,
        email=email,
        source="local",
        approved=True,
        email_confirmed=True,
        active=True,
        is_admin=False,
        note=note,
    )
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    flash(f"Utente {email} creato.")
    return redirect(_public_admin_users_url())


@auth_bp.route("/admin/users/<int:user_id>/approve", methods=["POST"])
def approve_user(user_id: int):
    guard = _admin_required()
    if guard:
        return guard

    user = User.query.get_or_404(user_id)
    if user.source != "local":
        abort(400)
    if not user.email_confirmed:
        flash("Impossibile approvare: email non ancora confermata dall'utente.")
        return redirect(_public_admin_users_url())

    user.approved = True
    db.session.commit()
    flash(f"Utente {user.username} approvato.")
    return redirect(_public_admin_users_url())


@auth_bp.route("/admin/users/<int:user_id>/delete", methods=["POST"])
def delete_user(user_id: int):
    guard = _admin_required()
    if guard:
        return guard

    user = User.query.get_or_404(user_id)
    if user.source != "local":
        abort(400)
    if user.is_admin:
        flash("Non puoi eliminare un utente amministratore.")
        return redirect(_public_admin_users_url())
    if user.id == current_user.id:
        flash("Non puoi eliminare il tuo utente admin corrente.")
        return redirect(_public_admin_users_url())

    db.session.delete(user)
    db.session.commit()
    flash(f"Utente {user.username} eliminato.")
    return redirect(_public_admin_users_url())


@auth_bp.route("/admin/users/<int:user_id>/disable", methods=["POST"])
def disable_user(user_id: int):
    guard = _admin_required()
    if guard:
        return guard

    user = User.query.get_or_404(user_id)
    if user.source != "local":
        abort(400)
    if user.is_admin:
        flash("Non puoi disabilitare un utente amministratore.")
        return redirect(_public_admin_users_url())
    if user.id == current_user.id:
        flash("Non puoi disabilitare il tuo utente admin corrente.")
        return redirect(_public_admin_users_url())

    user.active = False
    db.session.commit()
    flash(f"Utente {user.username} disabilitato.")
    return redirect(_public_admin_users_url())


@auth_bp.route("/admin/users/<int:user_id>/enable", methods=["POST"])
def enable_user(user_id: int):
    guard = _admin_required()
    if guard:
        return guard

    user = User.query.get_or_404(user_id)
    if user.source != "local":
        abort(400)
    if user.is_admin:
        flash("Un utente amministratore non richiede riabilitazione.")
        return redirect(_public_admin_users_url())

    user.active = True
    db.session.commit()
    flash(f"Utente {user.username} riabilitato.")
    return redirect(_public_admin_users_url())


@auth_bp.route("/admin/users/<int:user_id>/note", methods=["POST"])
def update_user_note(user_id: int):
    guard = _admin_required()
    if guard:
        return guard

    user = User.query.get_or_404(user_id)
    if user.source != "local":
        abort(400)

    user.note = (request.form.get("note", "") or "").strip()
    db.session.commit()
    flash(f"Nota aggiornata per {user.email}.")
    return redirect(_public_admin_users_url())
