from flask import Blueprint, request, redirect, url_for, render_template, flash, session
from flask_login import (
    LoginManager, login_user,
    logout_user, login_required, current_user
)
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv
from functools import wraps
import os
import re
import secrets
import requests
import ssl
import smtplib
from datetime import datetime, timedelta

from app import db
from app.models.user import User
from app.models.login_log import LoginLog
from app.models.event_log import EventLog
from app.models.reset_token import PasswordResetToken
from app.totp import verify_totp

load_dotenv()

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")
login_manager = LoginManager()
login_manager.login_view = "auth.login"


@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except:
        return None


def _log_event(message: str, category: str = "auth"):
    try:
        db.session.add(EventLog(message=message[:255], category=category[:64]))
        db.session.commit()
    except Exception:
        db.session.rollback()


def _client_ip() -> str:
    ip_raw = request.headers.get("X-Forwarded-For", request.remote_addr) or ""
    return ip_raw.split(",")[0].strip()


def log_auth_event(action: str, status: str, user: str | None = None, detail: str | None = None):
    username = user or (current_user.username if current_user.is_authenticated else "guest")
    message = f"{action} status={status} user={username} ip={_client_ip()}"
    if detail:
        message = f"{message} detail={detail}"
    _log_event(message, "auth")


def log_authz_event(action: str, status: str, user: str | None = None, detail: str | None = None):
    username = user or (current_user.username if current_user.is_authenticated else "guest")
    message = f"{action} status={status} user={username} ip={_client_ip()}"
    if detail:
        message = f"{message} detail={detail}"
    _log_event(message, "authz")


def admin_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            log_authz_event("admin_required", "denied", detail=request.path)
            flash("Administrator permissions required.", "danger")
            return redirect(url_for("dashboard.dashboard"))
        return f(*args, **kwargs)
    return decorated


def log_login_event(username: str, status: str):
    try:
        ip_raw = request.headers.get("X-Forwarded-For", request.remote_addr) or ""
        ip = ip_raw.split(",")[0].strip()
        ua = (request.headers.get("User-Agent") or "")[:255]
        entry = LoginLog(username=username, ip=ip, status=status, user_agent=ua)
        db.session.add(entry)
        db.session.commit()
    except Exception:
        db.session.rollback()


def create_temp_user(username, email=None, role="viewer", is_approved=False):
    if User.query.filter_by(username=username).first():
        return None

    temp_password = secrets.token_urlsafe(10)

    user = User(
        username=username,
        email=email or f"{username}@example.com",
        role=role or "viewer",
        is_temp_password=True,
        is_approved=is_approved,
        theme="dark",
        accent="sky",
    )
    user.set_password(temp_password)

    db.session.add(user)
    db.session.commit()

    return temp_password


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")

        if not username:
            flash("Username is required.", "danger")
            return render_template("register.html")

        if User.query.filter_by(username=username).first():
            flash("Username already exists.", "danger")
            return render_template("register.html")

        temp_pw = create_temp_user(username, email)
        log_auth_event("register", "submitted", username)

        flash(
            "Your account request was submitted. An administrator must approve your account before logging in.",
            "info",
        )
        return redirect(url_for("auth.login"))

    return render_template("register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    site_key = os.getenv("RECAPTCHA_SITE_KEY")

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        recaptcha_response = request.form.get("g-recaptcha-response")
        totp_code = request.form.get("totp_code", "").strip()

        if not recaptcha_response:
            log_auth_event("login", "failed_captcha", username or "unknown")
            flash("Please complete the CAPTCHA.", "danger")
            return render_template("login.html", site_key=site_key)

        secret_key = os.getenv("RECAPTCHA_SECRET_KEY")
        verify = requests.post(
            "https://www.google.com/recaptcha/api/siteverify",
            data={"secret": secret_key, "response": recaptcha_response},
        ).json()

        if not verify.get("success"):
            log_auth_event("login", "failed_captcha", username or "unknown")
            flash("CAPTCHA verification failed.", "danger")
            return render_template("login.html", site_key=site_key)

        user = User.query.filter_by(username=username).first()

        if not user:
            log_auth_event("login", "failed_no_user", username or "unknown")
            log_login_event(username or "unknown", "failed_no_user")
            flash("Invalid username or password.", "danger")
            return render_template("login.html", site_key=site_key)

        if not user.check_password(password):
            log_auth_event("login", "failed_bad_password", username or "unknown")
            log_login_event(username, "failed_bad_password")
            flash("Invalid username or password.", "danger")
            return render_template("login.html", site_key=site_key)

        # Admins bypass the approval gate so they can always log in.
        if not user.is_approved and not user.is_admin():
            log_auth_event("login", "blocked_pending_approval", username or "unknown")
            log_login_event(username, "blocked_pending_approval")
            flash("Your account is pending administrator approval.", "warning")
            return render_template("login.html", site_key=site_key)

        if user.is_2fa_enabled:
            clean_code = re.sub(r"\\D", "", totp_code or "")
            if not clean_code or not verify_totp(user.totp_secret, clean_code):
                log_auth_event("login", "failed_2fa", username or "unknown")
                log_login_event(username, "failed_2fa")
                flash("Invalid 2FA code.", "danger")
                return render_template("login.html", site_key=site_key)

        login_user(user)
        session.permanent = True
        session["last_activity"] = datetime.utcnow().timestamp()
        log_login_event(username, "success")
        log_auth_event("login", "success", username)

        if user.is_temp_password:
            session["force_password_change"] = True
            flash("Please change your temporary password.", "warning")
            return redirect(url_for("auth.change_password"))

        flash("Login successful!", "success")
        return redirect(url_for("dashboard.dashboard"))

    return render_template("login.html", site_key=site_key)


@auth_bp.route("/logout")
@login_required
def logout():
    session.pop("admin_verified", None)
    try:
        log_login_event(current_user.username if current_user else "unknown", "logout")
        log_auth_event("logout", "success")
    except Exception:
        pass
    logout_user()
    flash("Logged out.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    user = User.query.filter_by(username=current_user.username).first()

    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("auth.logout"))

    force_reset = session.get("force_password_change", False)

    if request.method == "POST":
        current_pw = request.form.get("current_password")
        new_pw = request.form.get("new_password")
        confirm_pw = request.form.get("confirm_password")

        # Skip current-password check when the user is being forced to change a temp password.
        if not force_reset:
            if not current_pw or not user.check_password(current_pw):
                flash("Current password incorrect.", "danger")
                return render_template("change_password.html", force_reset=force_reset)

        if new_pw != confirm_pw:
            flash("Passwords do not match.", "danger")
            return render_template("change_password.html", force_reset=force_reset)

        if len(new_pw) < 15 or not re.search(r"\d", new_pw) or not re.search(r"[^A-Za-z0-9]", new_pw):
            flash("Password must be 15+ chars, include a number and a symbol.", "danger")
            return render_template("change_password.html", force_reset=force_reset)

        user.set_password(new_pw)
        user.is_temp_password = False
        db.session.commit()
        session.pop("force_password_change", None)

        flash("Password changed successfully.", "success")
        log_auth_event("password_change", "success", user.username)
        return redirect(url_for("auth.login"))

    return render_template("change_password.html", force_reset=force_reset)


def _smtp_config():
    return {
        "host": os.getenv("SMTP_HOST"),
        "port": int(os.getenv("SMTP_PORT", "587")),
        "user": os.getenv("SMTP_USERNAME"),
        "password": os.getenv("SMTP_PASSWORD"),
        "sender": os.getenv("SMTP_FROM"),
        "alias": os.getenv("SMTP_FROM_ALIAS"),
        "use_tls": os.getenv("SMTP_USE_TLS", "true").lower() != "false",
    }


def _send_email(to_email: str, subject: str, body: str):
    cfg = _smtp_config()
    if not all([cfg["host"], cfg["port"], cfg["user"], cfg["password"], cfg["sender"]]):
        return False, "SMTP not configured"

    from_header = cfg["sender"]
    if cfg["alias"]:
        from_header = f"{cfg['alias']} <{cfg['sender']}>"

    message = (
        f"From: {from_header}\r\n"
        f"To: {to_email}\r\n"
        f"Subject: {subject}\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "\r\n"
        f"{body}"
    )

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(cfg["host"], cfg["port"]) as server:
            if cfg["use_tls"]:
                server.starttls(context=context)
            server.login(cfg["user"], cfg["password"])
            server.sendmail(cfg["sender"], [to_email], message)
        return True, None
    except Exception as exc:
        return False, str(exc)


@auth_bp.route("/forgot", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip()
        if not email:
            flash("Please enter your email address.", "danger")
            return render_template("forgot_password.html")

        user = User.query.filter_by(email=email).first()
        if not user:
            log_auth_event("password_reset_request", "unknown_email", detail=email)
            flash("If that email exists, a reset link has been sent.", "info")
            return redirect(url_for("auth.login"))

        token = secrets.token_urlsafe(32)
        expires = datetime.utcnow() + timedelta(hours=1)
        reset_entry = PasswordResetToken(
            user_id=user.id, token=token, expires_at=expires, used=False
        )
        db.session.add(reset_entry)
        db.session.commit()

        reset_link = url_for("auth.reset_password", token=token, _external=True)
        body = (
            f"Hello {user.username},\n\n"
            "We received a request to reset your password.\n"
            f"Reset link: {reset_link}\n\n"
            "If you did not request this, you can ignore this email.\n"
            "This link expires in 1 hour."
        )

        sent, err = _send_email(user.email, "Password Reset", body)
        if not sent:
            log_auth_event("password_reset_request", "email_failed", user.username, detail=err or "smtp_error")
            flash(f"Could not send reset email: {err}", "danger")
            return render_template("forgot_password.html")

        log_auth_event("password_reset_request", "sent", user.username)
        flash("If that email exists, a reset link has been sent.", "info")
        return redirect(url_for("auth.login"))

    return render_template("forgot_password.html")


@auth_bp.route("/reset/<token>", methods=["GET", "POST"])
def reset_password(token):
    reset_entry = PasswordResetToken.query.filter_by(token=token).first()
    if not reset_entry or reset_entry.used or reset_entry.expires_at < datetime.utcnow():
        log_auth_event("password_reset", "invalid_or_expired", detail="token_invalid_or_expired")
        flash("Invalid or expired reset link.", "danger")
        return redirect(url_for("auth.login"))

    user = User.query.get(reset_entry.user_id)
    if not user:
        log_auth_event("password_reset", "user_not_found", detail=str(reset_entry.user_id))
        flash("User not found.", "danger")
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        new_pw = request.form.get("new_password")
        confirm_pw = request.form.get("confirm_password")

        if new_pw != confirm_pw:
            flash("Passwords do not match.", "danger")
            return render_template("reset_password.html")

        if len(new_pw) < 15 or not re.search(r"\d", new_pw) or not re.search(r"[^A-Za-z0-9]", new_pw):
            flash("Password must be 15+ chars, include a number and a symbol.", "danger")
            return render_template("reset_password.html")

        user.set_password(new_pw)
        user.is_temp_password = False
        reset_entry.used = True
        db.session.commit()

        flash("Password reset successfully. You can now log in.", "success")
        log_auth_event("password_reset", "success", user.username)
        return redirect(url_for("auth.login"))

    return render_template("reset_password.html")
