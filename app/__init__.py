# app/__init__.py

from flask import Flask, session
from flask_session import Session
from datetime import timedelta
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
import os

# ======================================================
# Load environment first
# ======================================================
load_dotenv()

db = SQLAlchemy()
csrf = CSRFProtect()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per hour"],
    storage_uri="memory://"
)


def create_app():
    app = Flask(__name__)

    # ==================================================
    # Security / Keys
    # ==================================================
    app.secret_key = os.getenv("SECRET_KEY", "REPLACE_WITH_A_SECURE_RANDOM_KEY")

    # ==================================================
    # Database
    # ==================================================
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_size": int(os.getenv("DB_POOL_SIZE", "5")),
        "max_overflow": int(os.getenv("DB_MAX_OVERFLOW", "10")),
        "pool_pre_ping": True,
        "pool_recycle": 1800,
    }

    # ==================================================
    # reCAPTCHA
    # ==================================================
    app.config["RECAPTCHA_PUBLIC_KEY"] = os.getenv("RECAPTCHA_SITE_KEY")
    app.config["RECAPTCHA_PRIVATE_KEY"] = os.getenv("RECAPTCHA_SECRET_KEY")

    # ==================================================
    # Session Persistence
    # ==================================================
    app.config["SESSION_TYPE"] = "filesystem"
    app.config["SESSION_PERMANENT"] = True
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=1)
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = False  # set to True when HTTPS enabled

    # ==================================================
    # File uploads (profile images)
    # ==================================================
    app.config["UPLOAD_FOLDER"] = os.path.join(app.root_path, "static", "profiles")
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    # ==================================================
    # CSRF + Rate Limiting
    # ==================================================
    app.config["WTF_CSRF_ENABLED"] = True
    app.config["WTF_CSRF_CHECK_DEFAULT"] = False

    Session(app)
    csrf.init_app(app)
    limiter.init_app(app)
    db.init_app(app)

    # ==================================================
    # Blueprints
    # ==================================================
    from app.auth import auth_bp, login_manager
    from app.dashboard import dashboard_bp
    from app.routes.access import access_bp
    from app.routes.settings import settings_bp
    from app.admin import admin_bp
    from app.routes.logs import bp_logs

    login_manager.init_app(app)

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(access_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(bp_logs)

    # ==================================================
    # Database Initialization (tables)
    # ==================================================
    with app.app_context():
        db.create_all()

    # ==================================================
    # Global Template Variables (theme / accent / role)
    # ==================================================
    @app.context_processor
    def inject_globals():
        """
        Automatically provides:
          - theme
          - accent
          - role
          - temp_unit
        to every template.
        """
        from flask_login import current_user

        default_theme = "dark"
        default_accent = "sky"
        role = "guest"
        temp_unit = "C"

        if current_user.is_authenticated:
            theme = getattr(current_user, "theme", default_theme) or default_theme
            accent = getattr(current_user, "accent", default_accent) or default_accent
            role = getattr(current_user, "role", "user") or "user"
            temp_unit = getattr(current_user, "temp_unit", temp_unit) or temp_unit
        else:
            theme = session.get("theme", default_theme)
            accent = session.get("accent", default_accent)
            temp_unit = session.get("temp_unit", temp_unit)

        return {
            "theme": theme,
            "accent": accent,
            "role": role,
            "temp_unit": temp_unit,
        }

    # ==================================================
    # Security Headers
    # ==================================================
    @app.after_request
    def apply_security_headers(response):
        csp = (
            "default-src 'self'; "
            "img-src 'self' data:; "
            "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com "
            "https://www.gstatic.com https://www.google.com https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline'; "
            "frame-src https://www.google.com; "
            "connect-src 'self';"
        )
        response.headers["Content-Security-Policy"] = csp
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response

    # ==================================================
    # Basic Routes
    # ==================================================
    @app.route("/")
    def home():
        return "<meta http-equiv='refresh' content='0; url=/auth/login'>"

    @app.route("/status")
    def status():
        return "Flask is running! Visit /dashboard to view your interface."

    return app
