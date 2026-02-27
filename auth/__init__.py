import os

from dotenv import load_dotenv
from flask import Flask
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from sqlalchemy import inspect, text

from .config import Config
from .models import User, db

login_manager = LoginManager()
login_manager.login_view = "auth.login"
csrf = CSRFProtect()


@login_manager.user_loader
def load_user(user_id: str):
    return User.query.get(int(user_id))


def create_app() -> Flask:
    load_dotenv()
    app = Flask(__name__)
    app.config.from_object(Config)
    if app.config["SECRET_KEY"] in {
        "dev-only-secret-change-me",
        "change-this-secret",
    }:
        raise RuntimeError(
            "FLASK_SECRET_KEY non configurata: imposta una chiave robusta nel file .env."
        )

    os.makedirs(app.instance_path, exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    from .auth import auth_bp

    app.register_blueprint(auth_bp, url_prefix="/auth")

    def _ensure_schema():
        inspector = inspect(db.engine)
        if "user" not in inspector.get_table_names():
            return

        existing_cols = {c["name"] for c in inspector.get_columns("user")}
        stmts = []
        if "approved" not in existing_cols:
            stmts.append("ALTER TABLE user ADD COLUMN approved BOOLEAN DEFAULT 1")
        if "email_confirmed" not in existing_cols:
            stmts.append("ALTER TABLE user ADD COLUMN email_confirmed BOOLEAN DEFAULT 1")
        if "is_admin" not in existing_cols:
            stmts.append("ALTER TABLE user ADD COLUMN is_admin BOOLEAN DEFAULT 0")
        if "note" not in existing_cols:
            stmts.append("ALTER TABLE user ADD COLUMN note TEXT DEFAULT ''")
        if not stmts:
            return

        with db.engine.begin() as conn:
            for stmt in stmts:
                conn.execute(text(stmt))

    @app.cli.command("init-db")
    def init_db_command():
        db.create_all()
        _ensure_schema()
        print("Database inizializzato.")

    @app.cli.command("create-admin")
    def create_admin_command():
        email = input("Email admin: ").strip().lower()
        password = input("Password admin: ").strip()
        username = email

        if not email or not password:
            print("Campi mancanti.")
            return

        existing = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        if existing:
            existing.is_admin = True
            existing.approved = True
            existing.email_confirmed = True
            existing.active = True
            existing.source = existing.source or "local"
            if existing.source == "local":
                existing.username = email
                existing.email = email
                existing.set_password(password)
            db.session.commit()
            print("Utente esistente aggiornato a admin.")
            return

        user = User(
            username=username,
            email=email,
            source="local",
            approved=True,
            email_confirmed=True,
            is_admin=True,
            active=True,
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        print("Admin creato.")

    @app.cli.command("change-admin")
    def change_admin_command():
        current_login = input("Username o email admin attuale: ").strip().lower()
        new_username = input("Nuovo username (invio = invariato): ").strip().lower()
        new_email = input("Nuova email (invio = invariata): ").strip().lower()
        new_password = input("Nuova password (invio = invariata): ").strip()

        if not current_login:
            print("Username/email admin attuale mancante.")
            return

        user = User.query.filter(
            ((User.username == current_login) | (User.email == current_login))
            & (User.is_admin.is_(True))
        ).first()
        if not user:
            print("Admin non trovato.")
            return

        target_username = new_username or user.username
        target_email = new_email or user.email

        if new_username:
            username_conflict = User.query.filter(
                (User.username == target_username) & (User.id != user.id)
            ).first()
            if username_conflict:
                print("Username gia' in uso da un altro utente.")
                return

        if new_email:
            email_conflict = User.query.filter(
                (User.email == target_email) & (User.id != user.id)
            ).first()
            if email_conflict:
                print("Email gia' in uso da un altro utente.")
                return

        user.username = target_username
        user.email = target_email

        if new_password:
            user.set_password(new_password)

        user.is_admin = True
        user.approved = True
        user.email_confirmed = True
        user.active = True
        db.session.commit()
        print(f"Admin aggiornato: username={user.username}, email={user.email}")

    return app
