import os


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.lower() in {"1", "true", "yes", "on"}


class Config:
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "dev-only-secret-change-me")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///auth.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = env_bool("SESSION_COOKIE_SECURE", True)
    SESSION_COOKIE_SAMESITE = os.getenv("SESSION_COOKIE_SAMESITE", "Lax")
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SECURE = env_bool("REMEMBER_COOKIE_SECURE", True)
    REMEMBER_COOKIE_SAMESITE = os.getenv("REMEMBER_COOKIE_SAMESITE", "Lax")

    LDAP_ENABLED = env_bool("LDAP_ENABLED", True)
    LDAP_SERVER_URI = os.getenv("LDAP_SERVER_URI", "")
    LDAP_USE_SSL = env_bool("LDAP_USE_SSL", False)
    LDAP_BASE_DN = os.getenv("LDAP_BASE_DN", "")
    LDAP_SEARCH_FILTER = os.getenv("LDAP_SEARCH_FILTER", "(uid={username})")
    LDAP_BIND_DN = os.getenv("LDAP_BIND_DN", "")
    LDAP_BIND_PASSWORD = os.getenv("LDAP_BIND_PASSWORD", "")
    LDAP_USER_DN_TEMPLATE = os.getenv("LDAP_USER_DN_TEMPLATE", "")

    MAIL_ENABLED = env_bool("MAIL_ENABLED", False)
    MAIL_HOST = os.getenv("MAIL_HOST", "")
    MAIL_PORT = int(os.getenv("MAIL_PORT", "25"))
    MAIL_USE_TLS = env_bool("MAIL_USE_TLS", True)
    MAIL_USERNAME = os.getenv("MAIL_USERNAME", "")
    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD", "")
    MAIL_FROM = os.getenv("MAIL_FROM", "no-reply@example.org")
    ADMIN_NOTIFY_EMAIL = os.getenv("ADMIN_NOTIFY_EMAIL", "")
    LOGO_URL = os.getenv("LOGO_URL", "").strip()
    REGISTER_ALLOW_ANY_DOMAIN = env_bool("REGISTER_ALLOW_ANY_DOMAIN", False)
    REGISTER_ALLOWED_DOMAINS = os.getenv(
        "REGISTER_ALLOWED_DOMAINS", os.getenv("REGISTER_ALLOWED_DOMAIN", "cnr.it")
    )

    APP_BASE_URL = os.getenv("APP_BASE_URL", "")
    PUBLIC_LOGIN_PATH = os.getenv("PUBLIC_LOGIN_PATH", "/auth/login")
    PUBLIC_LOGOUT_PATH = os.getenv("PUBLIC_LOGOUT_PATH", "/auth/logout")
    PUBLIC_REGISTER_PATH = os.getenv("PUBLIC_REGISTER_PATH", "/auth/register")
    PUBLIC_ADMIN_USERS_PATH = os.getenv("PUBLIC_ADMIN_USERS_PATH", "/auth/admin/users")
    PUBLIC_CONFIRM_EMAIL_PREFIX = os.getenv(
        "PUBLIC_CONFIRM_EMAIL_PREFIX", "/auth/confirm-email"
    )
    PUBLIC_SUGGEST_PATH = os.getenv("PUBLIC_SUGGEST_PATH", "/auth/suggest-users")
    LOGIN_SUGGEST_ENABLED = env_bool("LOGIN_SUGGEST_ENABLED", False)
    LOGIN_SUGGEST_MIN_CHARS = int(os.getenv("LOGIN_SUGGEST_MIN_CHARS", "3"))
    LOGIN_SUGGEST_RATE_LIMIT_PER_MIN = int(
        os.getenv("LOGIN_SUGGEST_RATE_LIMIT_PER_MIN", "120")
    )
    LOGIN_RATE_LIMIT_PER_MIN = int(os.getenv("LOGIN_RATE_LIMIT_PER_MIN", "30"))
    LOGIN_SUGGEST_LDAP_ENABLED = env_bool("LOGIN_SUGGEST_LDAP_ENABLED", False)
    LDAP_SUGGEST_FILTER = os.getenv("LDAP_SUGGEST_FILTER", "(uid={query}*)")
    EMAIL_CONFIRM_MAX_AGE_SECONDS = int(
        os.getenv("EMAIL_CONFIRM_MAX_AGE_SECONDS", "86400")
    )
