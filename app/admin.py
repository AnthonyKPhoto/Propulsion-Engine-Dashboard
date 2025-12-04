
# app/admin.py
# Created by Anthony Kaiser

from flask import (
    Blueprint, render_template, request, redirect,
    url_for, flash, session, jsonify, send_file, after_this_request
)
# Created by Anthony Kaiser
from flask_login import login_required, current_user
from app import db
from app.models.user import User
from app.models.login_log import LoginLog
from app.models.event_log import EventLog
from app.auth import admin_required, create_temp_user

import secrets
import subprocess
import os
import psutil
import netifaces
import glob
import time
import re
import smtplib
import ssl
import signal
import tempfile
from datetime import timezone
from zoneinfo import ZoneInfo
from sqlalchemy.engine.url import make_url

admin_bp = Blueprint("admin_bp", __name__, url_prefix="/admin")

UPDATE_PROCESS = None
UPDATE_LOG_PATH = "/tmp/jet_sysupdate.log"
SAMPLE_EVENTS = [
    "Ignition toggled ON by Anthony",
    "Fuel valve OPENED",
    "ESP32 disconnected",
    "High-temp alarm triggered",
    "Emergency stop activated",
]


# ======================================================
# HELPERS
# ======================================================
def _current_role():
    if not current_user.is_authenticated:
        return "guest", "guest"
    return current_user.username.lower(), (current_user.role or "user").lower()


def _is_admin_verified():
    if not current_user.is_authenticated:
        return False
    if not session.get("admin_verified"):
        return False

    username, role = _current_role()
    if role == "admin" or current_user.is_admin() or username == "anthony":
        return True
    return False


def _is_ajax_request():
    """Detect XMLHTTPRequest / fetch-style calls."""
    if request.headers.get("X-Requested-With", "").lower() == "xmlhttprequest":
        return True
    if request.accept_mimetypes["application/json"] >= request.accept_mimetypes["text/html"]:
        return True
    return False


def _serialize_user(user: User):
    """Return a minimal JSON-safe representation of a User."""
    if not user:
        return None
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "is_approved": user.is_approved,
        "approved_label": "Yes" if user.is_approved else "No",
    }


def _username_valid(username: str) -> bool:
    """Simple username validation: 3–32 chars, letters/numbers/underscore only."""
    if not username:
        return False
    if len(username) < 3 or len(username) > 32:
        return False
    return re.fullmatch(r"[A-Za-z0-9_]+", username) is not None


def _email_valid(email: str) -> bool:
    """Very light email validation."""
    if not email or len(email) > 255:
        return False
    # simple pattern; you can tighten later if you want
    return re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) is not None


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
        f"An administrator created an account for you.\n"
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


# ======================================================
# CPU TEMP SUPPORT
# ======================================================
def get_cpu_temp_c():
    try:
        temps = psutil.sensors_temperatures()
        if not temps:
            return None

        for key in ("cpu-thermal", "cpu_thermal", "coretemp", "soc_thermal"):
            if key in temps and temps[key]:
                return temps[key][0].current

        for entries in temps.values():
            if entries:
                return entries[0].current

    except Exception:
        return None

    return None


# ======================================================
# SYSTEM METRICS API
# ======================================================
@admin_bp.route("/system/metrics")
@login_required
@admin_required
def system_metrics():
    if not _is_admin_verified():
        return jsonify({"error": "Permission denied"}), 403

    cpu = psutil.cpu_percent(interval=0)
    ram = psutil.virtual_memory()
    disk = psutil.disk_usage("/")

    return jsonify({
        "cpu_percent": cpu,
        "ram_percent": ram.percent,
        "disk_percent": disk.percent,
        "cpu_temp_c": get_cpu_temp_c(),
    })


# ======================================================
# ADMIN VERIFY
# ======================================================
@admin_bp.route("/", methods=["GET", "POST"])
@login_required
@admin_required
def admin_verify():
    if session.get("admin_verified"):
        return redirect(url_for("admin_bp.admin_panel"))

    if request.method == "POST":
        password = request.form.get("password")
        user = User.query.get(int(current_user.id))

        if not user:
            flash("User not found.", "danger")
            return redirect(url_for("dashboard.dashboard"))

        if not user.check_password(password):
            flash("Incorrect password.", "danger")
            return render_template("admin/verify.html")

        if not user.is_admin() and user.username.lower() != "anthony":
            return render_template("admin/access_denied.html")

        session["admin_verified"] = True
        return render_template("admin/access_granted.html")

    return render_template("admin/verify.html")


# ======================================================
# ADMIN PANEL
# ======================================================
@admin_bp.route("/panel")
@login_required
@admin_required
def admin_panel():
    if not _is_admin_verified():
        return redirect(url_for("admin_bp.admin_verify"))

    _, role = _current_role()
    return render_template("admin/index.html", role=role)


# ======================================================
# USER & ROLE MANAGEMENT (FULL DB VERSION)
# ======================================================
@admin_bp.route("/users", methods=["GET", "POST"])
@login_required
@admin_required
def users():
    if not _is_admin_verified():
        if _is_ajax_request():
            return jsonify({"status": "error", "message": "Admin verification required."}), 403
        return redirect(url_for("admin_bp.admin_verify"))

    # ---------- POST (actions from modal) ----------
    if request.method == "POST":
        action = request.form.get("action", "").strip()
        user_id = request.form.get("user_id")

        is_ajax = _is_ajax_request()

        def respond(status: str, message: str, user_obj=None, http_status=200, category="info"):
            if is_ajax:
                return jsonify({
                    "status": status,
                    "message": message,
                    "user": _serialize_user(user_obj) if user_obj else None
                }), http_status
            else:
                flash(message, category)
                return redirect(url_for("admin_bp.users"))

        # ==============================
        # CREATE USER
        # ==============================
        if action == "create_user":
            new_username = request.form.get("new_username", "").strip()
            new_email = request.form.get("new_email", "").strip()
            new_role = request.form.get("new_role", "user").strip() or "user"

            if not _username_valid(new_username):
                return respond(
                    "error",
                    "Username must be 3–32 characters, letters/numbers/underscore only.",
                    http_status=400,
                    category="danger",
                )

            if new_email and not _email_valid(new_email):
                return respond("error", "Please enter a valid email address.", http_status=400, category="danger")

            if User.query.filter_by(username=new_username).first():
                return respond("error", "That username already exists.", http_status=400, category="danger")

            temp_pw = create_temp_user(
                new_username,
                email=new_email or None,
                role=new_role if new_role in ("admin", "user") else "user",
                is_approved=True,
            )

            if not temp_pw:
                return respond("error", "Could not create user.", http_status=500, category="danger")

            email_sent = False
            email_error = None
            if new_email:
                email_sent, email_error = _send_temp_password_email(new_email, new_username, temp_pw)

            session["last_temp_pw"] = temp_pw

            if email_sent:
                msg = f"User created. Temporary password emailed to {new_email}."
            else:
                msg = f"User created. Temporary password: {temp_pw}"
                if email_error:
                    msg += f" (email failed: {email_error})"

            return respond("ok", msg, None, 200, "success")

        if not user_id:
            return respond("error", "Missing user ID.", http_status=400, category="danger")

        try:
            user_id_int = int(user_id)
        except ValueError:
            return respond("error", "Invalid user ID.", http_status=400, category="danger")

        user = User.query.get(user_id_int)
        if not user:
            return respond("error", "User not found.", http_status=404, category="danger")

        # Protect the primary 'anthony' account from destructive changes
        is_protected_anthony = user.username.lower() == "anthony"

        # ==============================
        # CHANGE USERNAME
        # ==============================
        if action == "change_username":
            if is_protected_anthony:
                return respond("error", "Primary admin username cannot be changed.", user, 403, "danger")

            new_username = request.form.get("new_username", "").strip()

            if not _username_valid(new_username):
                return respond(
                    "error",
                    "Username must be 3–32 characters, letters/numbers/underscore only.",
                    user,
                    400,
                    "danger",
                )

            existing = User.query.filter_by(username=new_username).first()
            if existing and existing.id != user.id:
                return respond("error", "That username is already taken.", user, 400, "danger")

            user.username = new_username
            db.session.commit()
            return respond("ok", "Username updated successfully.", user, 200, "success")

        # ==============================
        # CHANGE EMAIL
        # ==============================
        elif action == "change_email":
            new_email = request.form.get("new_email", "").strip()

            if not _email_valid(new_email):
                return respond("error", "Please enter a valid email address.", user, 400, "danger")

            user.email = new_email
            db.session.commit()
            return respond("ok", "Email updated successfully.", user, 200, "success")

        # ==============================
        # RESET PASSWORD
        # ==============================
        elif action == "reset":
            new_pw = secrets.token_urlsafe(8)
            user.set_password(new_pw)
            user.is_temp_password = True
            db.session.commit()
            return respond(
                "ok",
                f"Password reset. New temporary password: {new_pw}",
                user,
                200,
                "warning",
            )

        # ==============================
        # ROLE TOGGLE
        # ==============================
        elif action == "role":
            if is_protected_anthony:
                return respond("error", "Primary admin role cannot be changed.", user, 403, "danger")

            user.role = "admin" if user.role == "user" else "user"
            db.session.commit()
            return respond("ok", f"Role changed → {user.role}", user, 200, "success")

        # ==============================
        # DELETE USER
        # ==============================
        elif action == "delete":
            if is_protected_anthony or user.is_admin():
                return respond("error", "Admin / protected accounts cannot be deleted.", user, 403, "danger")

            db.session.delete(user)
            db.session.commit()
            return respond("ok", "User deleted successfully.", None, 200, "success")

        # ==============================
        # APPROVE USER
        # ==============================
        elif action == "approve":
            user.is_approved = True
            db.session.commit()
            return respond("ok", "User approved.", user, 200, "success")

        # Unknown action
        return respond("error", "Unknown action.", user, 400, "danger")

    # ---------- GET: render page ----------
    all_users = User.query.order_by(User.created_at.desc()).all()
    temp_pw = session.pop("last_temp_pw", None)
    return render_template(
        "admin/user_list.html",
        users=all_users,
        role=_current_role()[1],
        temp_pw=temp_pw,
    )


# ======================================================
# LOGS (Placeholder)
# ======================================================
@admin_bp.route("/logs")
@login_required
@admin_required
def logs():
    if not _is_admin_verified():
        return redirect(url_for("admin_bp.admin_verify"))

    raw_logs = (
        LoginLog.query.order_by(LoginLog.timestamp.desc())
        .limit(200)
        .all()
    )
    est_tz = ZoneInfo("America/New_York")
    formatted_logs = []
    for log in raw_logs:
        ts = log.timestamp
        est_str = None
        if ts:
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            est = ts.astimezone(est_tz)
            est_str = est.strftime("%Y-%m-%d %I:%M:%S %p")
        formatted_logs.append({
            "username": log.username,
            "ip": log.ip,
            "status": log.status,
            "user_agent": log.user_agent,
            "timestamp_est": est_str,
        })

    return render_template("admin/logs.html", logs=formatted_logs)


# ======================================================
# NETWORK STATUS
# ======================================================
@admin_bp.route("/network/status/json")
@login_required
@admin_required
def network_status_json():
    if not _is_admin_verified():
        return jsonify({"error": "Permission denied"}), 403

    interfaces = {}
    for iface in netifaces.interfaces():
        info = {"ipv4": None, "ipv6": None, "mac": None, "up": False}
        try:
            addrs = netifaces.ifaddresses(iface)

            if netifaces.AF_INET in addrs:
                info["ipv4"] = addrs[netifaces.AF_INET][0].get("addr")

            if netifaces.AF_INET6 in addrs:
                info["ipv6"] = addrs[netifaces.AF_INET6][0].get("addr")

            if netifaces.AF_LINK in addrs:
                info["mac"] = addrs[netifaces.AF_LINK][0].get("addr")

            info["up"] = True
        except Exception:
            info["up"] = False

        interfaces[iface] = info

    try:
        g = netifaces.gateways()
        gateway = g.get("default", {}).get(netifaces.AF_INET, [None])[0]
    except Exception:
        gateway = None

    dns_servers = []
    try:
        with open("/etc/resolv.conf", "r") as f:
            for line in f:
                if line.startswith("nameserver"):
                    dns_servers.append(line.split()[1])
    except Exception:
        pass

    return jsonify({
        "interfaces": interfaces,
        "gateway": gateway,
        "dns": dns_servers,
        "timestamp": time.time()
    })


@admin_bp.route("/network/status")
@login_required
@admin_required
def network_status_page():
    if not _is_admin_verified():
        return redirect(url_for("admin_bp.admin_verify"))
    return render_template("admin/network_status.html")


# ======================================================
# PORT MONITORING
# ======================================================
@admin_bp.route("/network/ports/json")
@login_required
@admin_required
def network_ports_json():
    if not _is_admin_verified():
        return jsonify({"error": "Permission denied"}), 403

    connections = []
    for c in psutil.net_connections(kind="inet"):
        connections.append({
            "pid": c.pid,
            "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
            "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
            "status": c.status,
            "is_listening": (c.status == "LISTEN"),
        })

    serial_devices = (
        glob.glob("/dev/ttyUSB*") +
        glob.glob("/dev/ttyACM*") +
        glob.glob("/dev/ttyAMA*") +
        glob.glob("/dev/ttyS*")
    )

    return jsonify({
        "connections": connections,
        "serial_devices": serial_devices,
        "timestamp": time.time()
    })


@admin_bp.route("/network/ports")
@login_required
@admin_required
def network_ports_page():
    if not _is_admin_verified():
        return redirect(url_for("admin_bp.admin_verify"))
    return render_template("admin/port_monitoring.html")


# ======================================================
# RESTART / SHUTDOWN
# ======================================================
def _restart_service():
    """
    Try to restart the dashboard service. We allow an environment override for
    the service name so deployments (gunicorn, different unit names) can work
    without code changes.
    """
    service_env = os.getenv("JET_SERVICE_NAME")
    candidates = []
    if service_env:
        candidates.append(service_env)
    candidates.extend(["jet_dashboard.service", "gunicorn"])

    errors = []
    for svc in candidates:
        try:
            result = subprocess.run(
                ["sudo", "systemctl", "restart", svc],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return True, svc, None
            errors.append(f"{svc}: {result.stderr.strip() or result.stdout.strip()}")
        except FileNotFoundError:
            errors.append("sudo not found on system.")
            break
        except Exception as exc:
            errors.append(f"{svc}: {exc}")
    return False, None, "; ".join(errors)


def _run_cmd(cmd, env=None):
    """Run a shell command and return (ok, stdout, stderr)."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, env=env)
        return result.returncode == 0, (result.stdout or "").strip(), (result.stderr or "").strip()
    except FileNotFoundError as exc:
        return False, "", f"{cmd[0]} not found ({exc})"
    except Exception as exc:
        return False, "", str(exc)


def _restart_service():
    """
    Try to restart the dashboard service with a few strategies so deployments
    using different service names or process managers (gunicorn) still work.
    Priority:
      1) Custom command via JET_RESTART_CMD
      2) systemd restart using JET_SERVICE_NAME override or fallbacks
      3) HUP a gunicorn master PID (JET_GUNICORN_PID env or /run/gunicorn.pid)
    """
    # 1) Custom command override
    custom_cmd = os.getenv("JET_RESTART_CMD")
    if custom_cmd:
        ok, out, err = _run_cmd(["bash", "-c", custom_cmd])
        if ok:
            return True, custom_cmd, None
        return False, None, err or out or "Custom restart command failed"

    # 2) systemd service restart
    service_env = os.getenv("JET_SERVICE_NAME")
    candidates = []
    if service_env:
        candidates.append(service_env)
    candidates.extend(["jet_dashboard.service", "gunicorn"])

    errors = []
    for svc in candidates:
        ok, out, err = _run_cmd(["sudo", "systemctl", "restart", svc])
        if ok:
            return True, svc, None
        errors.append(f"{svc}: {err or out}")

    # 3) Gunicorn PID HUP
    gunicorn_pid_env = os.getenv("JET_GUNICORN_PID")
    gunicorn_pid_file = gunicorn_pid_env or "/run/gunicorn.pid"
    if os.path.exists(gunicorn_pid_file):
        try:
            with open(gunicorn_pid_file, "r") as f:
                pid_str = f.read().strip()
            if pid_str.isdigit():
                # try without sudo first
                ok, out, err = _run_cmd(["kill", "-HUP", pid_str])
                if not ok:
                    ok, out, err = _run_cmd(["sudo", "kill", "-HUP", pid_str])
                if ok:
                    return True, f"gunicorn pid {pid_str}", None
                errors.append(f"gunicorn pid {pid_str}: {err or out}")
        except Exception as exc:
            errors.append(f"gunicorn pid read: {exc}")

    # 4) Gunicorn master via psutil (last resort)
    try:
        masters = []
        for proc in psutil.process_iter(["name", "cmdline", "pid"]):
            name = (proc.info.get("name") or "").lower()
            cmd = " ".join(proc.info.get("cmdline") or []).lower()
            if "gunicorn" in name or "gunicorn" in cmd:
                if "master" in cmd or "master" in name:
                    masters.append(proc.pid)
        for pid in masters:
            try:
                os.kill(pid, signal.SIGHUP)
                return True, f"gunicorn master pid {pid}", None
            except Exception as exc:
                errors.append(f"gunicorn pid {pid}: {exc}")
    except Exception as exc:
        errors.append(f"gunicorn scan: {exc}")

    return False, None, "; ".join(errors) if errors else "Restart failed"


def _db_connection_info():
    url = os.getenv("DATABASE_URL")
    if not url:
        return None
    try:
        parsed = make_url(url)
        return {
            "host": parsed.host or "localhost",
            "port": str(parsed.port or 5432),
            "user": parsed.username,
            "password": parsed.password or "",
            "database": parsed.database,
        }
    except Exception:
        return None


@admin_bp.route("/system/restart", methods=["POST"])
@login_required
@admin_required
def restart_pi():
    if not _is_admin_verified():
        return jsonify({"error": "Permission denied"}), 403

    success, svc_name, err = _restart_service()
    if not success:
        return jsonify({"status": "error", "error": err or "Restart failed"}), 500

    return jsonify({"status": "ok", "service": svc_name})


@admin_bp.route("/system/shutdown", methods=["POST"])
@login_required
@admin_required
def shutdown_pi():
    if not _is_admin_verified():
        return jsonify({"error": "Permission denied"}), 403

    try:
        proc = subprocess.run(
            ["sudo", "shutdown", "-h", "now"],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            return (
                jsonify({"status": "error", "error": proc.stderr or proc.stdout}),
                500,
            )
    except FileNotFoundError:
        return jsonify({"status": "error", "error": "sudo not found"}), 500
    except Exception as exc:
        return jsonify({"status": "error", "error": str(exc)}), 500

    return jsonify({"status": "ok"})


# ======================================================
# SYSTEM UPDATE
# ======================================================
@admin_bp.route("/system-update/start", methods=["POST"])
@login_required
@admin_required
def system_update_start():
    global UPDATE_PROCESS

    if not _is_admin_verified():
        return jsonify({"error": "Permission denied"}), 403

    if UPDATE_PROCESS and UPDATE_PROCESS.poll() is None:
        return jsonify({"error": "Update already running", "running": True}), 400

    if os.path.exists(UPDATE_LOG_PATH):
        try:
            os.remove(UPDATE_LOG_PATH)
        except Exception:
            pass

    log = open(UPDATE_LOG_PATH, "w")

    update_cmd = os.getenv("JET_UPDATE_CMD", "apt update && apt -y upgrade")
    use_sudo = os.getenv("JET_UPDATE_USE_SUDO", "1") != "0"
    cmd = (["sudo"] if use_sudo else []) + ["bash", "-c", update_cmd]

    try:
        UPDATE_PROCESS = subprocess.Popen(
            cmd,
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except FileNotFoundError as exc:
        return jsonify({"error": f"Command not found: {exc}"}), 500
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

    return jsonify({"status": "started"})


@admin_bp.route("/system-update/status", methods=["GET"])
@login_required
@admin_required
def system_update_status():
    global UPDATE_PROCESS

    if not _is_admin_verified():
        return jsonify({"error": "Permission denied"}), 403

    output = ""
    if os.path.exists(UPDATE_LOG_PATH):
        try:
            with open(UPDATE_LOG_PATH, "r") as f:
                output = f.read()
        except Exception:
            pass

    exit_code = None
    running = False
    finished = False

    if UPDATE_PROCESS is not None:
        exit_code = UPDATE_PROCESS.poll()
        running = exit_code is None
        finished = exit_code is not None

    return jsonify({
        "output": output,
        "running": running,
        "finished": finished,
        "exit_code": exit_code
    })


# ======================================================
# EVENT LOGS (System Messages)
# ======================================================
def _ensure_sample_events():
    if EventLog.query.count() == 0:
        for msg in SAMPLE_EVENTS:
            db.session.add(EventLog(message=msg, category="info"))
        db.session.commit()


@admin_bp.route("/events/recent")
@login_required
@admin_required
def events_recent():
    if not _is_admin_verified():
        return jsonify({"error": "Permission denied"}), 403

    _ensure_sample_events()

    events = (
        EventLog.query.order_by(EventLog.created_at.desc())
        .limit(50)
        .all()
    )
    return jsonify({
        "events": [
            {
                "id": e.id,
                "message": e.message,
                "category": e.category,
                "created_at": e.created_at.isoformat() + "Z",
            }
            for e in events
        ]
    })


@admin_bp.route("/events/log", methods=["POST"])
@login_required
@admin_required
def events_log():
    if not _is_admin_verified():
        return jsonify({"status": "error", "error": "Permission denied"}), 403

    data = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()
    category = (data.get("category") or "info").strip() or "info"

    if not message:
        return jsonify({"status": "error", "error": "Message required"}), 400

    ev = EventLog(message=message[:255], category=category[:64])
    db.session.add(ev)
    db.session.commit()

    return jsonify({"status": "ok", "id": ev.id})


@admin_bp.route("/logs/last", methods=["GET"])
@login_required
def last_log_timestamp():
    """
    Lightweight endpoint to drive UI indicators: returns latest event log timestamp.
    """
    latest = EventLog.query.order_by(EventLog.created_at.desc()).first()
    return jsonify({
        "timestamp": latest.created_at.isoformat() + "Z" if latest else None
    })


# ======================================================
# BACKUP & RESTORE
# ======================================================
@admin_bp.route("/backup/download", methods=["GET"])
@login_required
@admin_required
def backup_download():
    if not _is_admin_verified():
        return redirect(url_for("admin_bp.admin_verify"))

    info = _db_connection_info()
    if not info:
        flash("DATABASE_URL not configured for backup.", "danger")
        return redirect(url_for("admin_bp.admin_panel"))

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".dump")
    tmp_path = tmp.name
    tmp.close()

    env = os.environ.copy()
    if info["password"]:
        env["PGPASSWORD"] = info["password"]

    cmd = [
        "pg_dump",
        "-Fc",
        "-h", info["host"],
        "-p", info["port"],
        "-U", info["user"],
        "-d", info["database"],
        "-f", tmp_path,
    ]

    ok, out, err = _run_cmd(cmd, env=env)
    if not ok:
        try:
            os.remove(tmp_path)
        except Exception:
            pass
        flash(f"Backup failed: {err or out or 'pg_dump error'}", "danger")
        return redirect(url_for("admin_bp.admin_panel"))

    @after_this_request
    def cleanup(response):
        try:
            os.remove(tmp_path)
        except Exception:
            pass
        return response

    filename = f"jet_dashboard_backup_{int(time.time())}.dump"
    return send_file(tmp_path, as_attachment=True, download_name=filename, mimetype="application/octet-stream")


@admin_bp.route("/backup/restore", methods=["POST"])
@login_required
@admin_required
def backup_restore():
    if not _is_admin_verified():
        return jsonify({"status": "error", "error": "Admin verification required."}), 403

    if "backup_file" not in request.files:
        return jsonify({"status": "error", "error": "No file uploaded."}), 400

    file = request.files["backup_file"]
    if not file.filename:
        return jsonify({"status": "error", "error": "No file selected."}), 400

    info = _db_connection_info()
    if not info:
        return jsonify({"status": "error", "error": "DATABASE_URL not configured."}), 500

    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp_path = tmp.name
    file.save(tmp_path)
    tmp.close()

    env = os.environ.copy()
    if info["password"]:
        env["PGPASSWORD"] = info["password"]

    lower_name = file.filename.lower()
    if lower_name.endswith((".dump", ".backup")):
        cmd = [
            "pg_restore",
            "--clean",
            "--if-exists",
            "--no-owner",
            "-h", info["host"],
            "-p", info["port"],
            "-U", info["user"],
            "-d", info["database"],
            tmp_path,
        ]
    else:
        cmd = [
            "psql",
            "-h", info["host"],
            "-p", info["port"],
            "-U", info["user"],
            "-d", info["database"],
            "-f", tmp_path,
        ]

    ok, out, err = _run_cmd(cmd, env=env)

    try:
        os.remove(tmp_path)
    except Exception:
        pass

    if not ok:
        return jsonify({"status": "error", "error": err or out or "Restore failed"}), 500

    return jsonify({"status": "ok"})
