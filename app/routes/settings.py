from flask import (
    Blueprint, render_template, request, session,
    redirect, url_for, flash, current_app
)
from flask_login import login_required, current_user

from app import db
from app.models.user import User
from app.totp import generate_base32_secret, verify_totp
from app.auth import admin_required, log_auth_event

import os
import uuid
import io
import base64
import re
from werkzeug.utils import secure_filename

settings_bp = Blueprint("settings_bp", __name__, url_prefix="/dashboard")

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}

def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@settings_bp.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    user = User.query.get(int(current_user.id))

    if not user:
        flash("User record not found.", "danger")
        return redirect(url_for("dashboard.dashboard"))

    def render_settings(pending_secret_override=None):
        pending_secret = pending_secret_override or session.get("pending_2fa_secret")
        otp_uri = None
        qr_base64 = None
        qr_supported = True
        qr_error = None
        if pending_secret:
            otp_uri = f"otpauth://totp/HybridTurbojet:{user.username}?secret={pending_secret}&issuer=HybridTurbojet"
            try:
                import qrcode  # type: ignore
                img = qrcode.make(otp_uri)
                buf = io.BytesIO()
                img.save(buf, format="PNG")
                qr_base64 = base64.b64encode(buf.getvalue()).decode("ascii")
            except Exception as exc:
                qr_supported = False
                qr_error = str(exc)

        return render_template(
            "settings.html",
            username=user.username,
            email=user.email,
            theme=user.theme,
            accent=user.accent,
            telemetry_enabled=user.telemetry_enabled,
            temp_unit=user.temp_unit,
            profile_image=user.profile_image if hasattr(user, "profile_image") else None,
            pending_2fa_secret=pending_secret,
            otp_uri=otp_uri,
            qr_base64=qr_base64,
            qr_supported=qr_supported,
            qr_error=qr_error,
        )

    if request.method == "POST":

        action = request.form.get("action", "update").strip()

        if action == "start_2fa":
            secret = generate_base32_secret()
            session["pending_2fa_secret"] = secret
            flash("Scan the secret with your authenticator app, then enter a code to confirm.", "info")
            return render_settings(pending_secret_override=secret)

        if action == "confirm_2fa":
            code_raw = (request.form.get("totp_code") or "").strip()
            code = re.sub(r"\D", "", code_raw)
            secret = session.get("pending_2fa_secret")
            if not secret:
                flash("No 2FA setup in progress. Start again.", "danger")
                return redirect(url_for("settings_bp.settings"))

            if not verify_totp(secret, code):
                flash("Invalid or expired 2FA code. Try again.", "danger")
                return redirect(url_for("settings_bp.settings"))

            user.totp_secret = secret
            user.is_2fa_enabled = True
            db.session.commit()
            session.pop("pending_2fa_secret", None)
            flash("Two-factor authentication enabled.", "success")
            log_auth_event("2fa", "enabled", user.username)
            return redirect(url_for("settings_bp.settings"))

        if action == "disable_2fa":
            user.totp_secret = None
            user.is_2fa_enabled = False
            db.session.commit()
            session.pop("pending_2fa_secret", None)
            flash("Two-factor authentication disabled.", "info")
            log_auth_event("2fa", "disabled", user.username)
            return redirect(url_for("settings_bp.settings"))

        new_username = (request.form.get("username", user.username) or "").strip()
        raw_email = (request.form.get("email") or "").strip()
        new_email = raw_email or user.email
        theme = request.form.get("theme", user.theme)
        accent = request.form.get("accent", user.accent)
        telemetry_enabled = "telemetry_enabled" in request.form
        temp_unit = request.form.get("temp_unit", user.temp_unit)

        if not new_username:
            flash("Username cannot be empty.", "danger")
            return redirect(url_for("settings_bp.settings"))

        existing = User.query.filter(
            User.username == new_username,
            User.id != user.id
        ).first()

        if existing:
            flash("Username is already taken.", "danger")
            return redirect(url_for("settings_bp.settings"))

        if raw_email:
            if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", raw_email):
                flash("Please enter a valid email address.", "danger")
                return redirect(url_for("settings_bp.settings"))

        user.username = new_username
        user.email = new_email
        user.theme = theme or "dark"
        user.accent = accent or "sky"
        user.telemetry_enabled = telemetry_enabled
        user.temp_unit = temp_unit or "C"

        db.session.commit()

        session["username"] = user.username
        session["email"] = user.email
        session["theme"] = user.theme
        session["accent"] = user.accent
        session["temp_unit"] = user.temp_unit

        # Re-login to refresh current_user attributes for this request.
        try:
            from flask_login import login_user
            login_user(user)
        except Exception:
            pass

        flash("Settings updated successfully.", "success")
        log_auth_event("settings_update", "success", user.username)
        return redirect(url_for("settings_bp.settings"))

    return render_settings()


@settings_bp.route("/upload_profile", methods=["POST"])
@login_required
def upload_profile():
    user = User.query.get(int(current_user.id))

    if "profile_image" not in request.files:
        flash("No file uploaded.", "danger")
        return redirect(url_for("settings_bp.settings"))

    file = request.files["profile_image"]

    if file.filename == "":
        flash("No file selected.", "danger")
        return redirect(url_for("settings_bp.settings"))

    if file and allowed_file(file.filename):
        ext = file.filename.rsplit(".", 1)[1].lower()
        filename = secure_filename(f"{uuid.uuid4().hex}.{ext}")
        save_path = os.path.join(current_app.config["UPLOAD_FOLDER"], filename)

        file.save(save_path)

        user.profile_image = filename
        db.session.commit()

        flash("Profile picture updated.", "success")
        log_auth_event("profile_image_update", "success", user.username)
        return redirect(url_for("settings_bp.settings"))

    flash("Invalid file type. Allowed: png, jpg, jpeg, webp.", "danger")
    return redirect(url_for("settings_bp.settings"))
