from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from datetime import datetime
from .. import db                     # ✅ fixed circular import (was: from app import db)
from ..models import User, AccessRequest            # ✅ corrected relative import
import requests
import secrets
import os
from argon2 import PasswordHasher
import ssl
import smtplib
from app.auth import create_temp_user
from flask import current_app

access_bp = Blueprint("access", __name__)
ph = PasswordHasher()


# ---------- ACCESS REQUEST FORM ----------
@access_bp.route('/request_access', methods=['GET', 'POST'])
def request_access():
    site_key = os.getenv("RECAPTCHA_SITE_KEY")
    if request.method == 'POST':
        username = (request.form.get("username") or "").strip()
        email = (request.form.get("email") or "").strip()
        reason = (request.form.get("reason") or "").strip()

        if not username or not email:
            flash("Username and email are required.", "danger")
            return render_template('request_access.html', site_key=site_key)

        recaptcha_response = request.form.get('g-recaptcha-response')
        secret_key = os.getenv("RECAPTCHA_SECRET_KEY")
        verify_url = "https://www.google.com/recaptcha/api/siteverify"

        if not recaptcha_response:
            flash("Please complete the CAPTCHA.", "danger")
            return render_template('request_access.html', site_key=site_key)

        response = requests.post(verify_url, data={
            'secret': secret_key,
            'response': recaptcha_response
        })
        result = response.json()

        if not result.get("success"):
            flash("CAPTCHA verification failed. Please try again.", "danger")
            return render_template('request_access.html', site_key=site_key)

        req = AccessRequest(
            username=username,
            email=email,
            reason=reason,
            status="pending",
            created_at=datetime.utcnow(),
        )
        db.session.add(req)
        db.session.commit()

        flash("Access request submitted successfully.", "success")

    return render_template('request_access.html', site_key=site_key)


# ---------- ADMIN: VIEW REQUESTS ----------
@access_bp.route("/admin/requests")
@login_required
def view_requests():
    """Admin page for reviewing access requests"""
    if current_user.role != "admin":
        flash("Access denied.", "danger")
        return redirect(url_for("dashboard.dashboard"))

    pending = AccessRequest.query.filter_by(status="pending").order_by(AccessRequest.created_at.desc()).all()
    decided = AccessRequest.query.filter(AccessRequest.status != "pending").order_by(AccessRequest.approval_time.desc()).all()
    return render_template("admin_requests.html", pending=pending, decided=decided)


# ---------- ADMIN: HANDLE REQUESTS ----------
@access_bp.route("/admin/requests/<int:id>/<action>")
@login_required
def handle_request(id, action):
    """Approve or deny pending access requests"""
    if current_user.role != "admin":
        flash("Unauthorized.", "danger")
        return redirect(url_for("dashboard.dashboard"))

    req = AccessRequest.query.get(id)
    if not req:
        flash("Request not found.", "warning")
        return redirect(url_for("access.view_requests"))

    if action == "approve":
        temp_pw = create_temp_user(req.username, email=req.email, role="user", is_approved=True)
        if not temp_pw:
            flash("Could not create user (maybe username exists).", "danger")
            return redirect(url_for("access.view_requests"))

        # Send email
        sent, err = _send_temp_password_email(req.email, req.username, temp_pw)
        if sent:
            flash("User approved and email sent with temporary password.", "success")
        else:
            flash(f"User approved. Email failed: {err}", "warning")

        req.status = "approved"
        req.approval_time = datetime.utcnow()
        req.temp_password_shown = True
        db.session.commit()

    elif action == "deny":
        req.status = "denied"
        req.approval_time = datetime.utcnow()
        db.session.commit()
        flash("Request denied.", "info")

    return redirect(url_for("access.view_requests"))


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


def _send_temp_password_email(to_email: str, username: str, temp_pw: str):
    cfg = _smtp_config()
    if not all([cfg["host"], cfg["port"], cfg["user"], cfg["password"], cfg["sender"]]):
        return False, "SMTP not configured"

    from_header = cfg["sender"]
    if cfg["alias"]:
        from_header = f"{cfg['alias']} <{cfg['sender']}>"

    body = (
        f"Hello {username},\n\n"
        f"Your access request was approved.\n"
        f"Username: {username}\n"
        f"Temporary password: {temp_pw}\n\n"
        "Log in with this password and you will be prompted to set a new one.\n"
        "If you did not expect this email, please ignore it.\n"
    )

    message = (
        f"From: {from_header}\r\n"
        f"To: {to_email}\r\n"
        "Subject: Your temporary password\r\n"
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
