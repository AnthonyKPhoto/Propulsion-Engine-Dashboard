import os
import subprocess
import sys

from flask import Blueprint, abort, jsonify, render_template, request
from flask_login import current_user, login_required
from flask_wtf.csrf import generate_csrf, validate_csrf
from wtforms.validators import ValidationError

from app.control_approval import current_state, handle_control_action

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/dashboard")

# Subprocess handle for the logger process
_logger_process: subprocess.Popen | None = None


@dashboard_bp.route("/")
@login_required
def dashboard():
    return render_template(
        "dashboard.html",
        csrf_token=generate_csrf(),
        initial_control_state=current_state(),
    )


@dashboard_bp.route("/logs")
@login_required
def logs():
    return render_template("logs.html")


@dashboard_bp.route("/settings")
@login_required
def settings_redirect():
    return render_template("settings.html")


def _require_csrf():
    token = request.headers.get("X-CSRFToken") or request.form.get("csrf_token")
    if not token:
        abort(400, description="Missing CSRF token.")
    try:
        validate_csrf(token)
    except ValidationError as exc:  # type: ignore
        abort(400, description=f"Invalid CSRF token: {exc}")


@dashboard_bp.route("/api/control/action", methods=["POST"])
@login_required
def control_action():
    _require_csrf()
    payload = request.get_json(silent=True) or {}
    action = (payload.get("action") or "").strip()
    request_id = payload.get("request_id")
    if not action:
        abort(400, description="Missing control action.")
    body, status = handle_control_action(current_user, action, request_id=request_id)
    return jsonify(body), status


@dashboard_bp.route("/api/alarm/set", methods=["POST"])
@login_required
def alarm_set():
    _require_csrf()
    payload = request.get_json(silent=True) or {}
    try:
        threshold = float(payload.get("threshold", 0))
    except (TypeError, ValueError):
        return jsonify({"ok": False, "message": "Invalid threshold value."}), 400
    from app.control_approval import set_alarm_threshold
    set_alarm_threshold(threshold)
    return jsonify({"ok": True, "threshold": threshold})


# ── Logger process control ────────────────────────────────────────────────────

def _logger_running() -> bool:
    return _logger_process is not None and _logger_process.poll() is None


@dashboard_bp.route("/api/logging/status")
@login_required
def logging_status():
    return jsonify({"running": _logger_running()})


@dashboard_bp.route("/api/logging/start", methods=["POST"])
@login_required
def logging_start():
    global _logger_process
    _require_csrf()

    role = getattr(current_user, "role_key", "viewer")
    if role not in ("operator", "admin"):
        return jsonify({"ok": False, "running": False, "message": "Operator or admin role required."}), 403

    if _logger_running():
        return jsonify({"ok": True, "running": True, "message": "Logger already running."})

    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logger.py")
    try:
        _logger_process = subprocess.Popen(
            [sys.executable, script],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return jsonify({"ok": True, "running": True, "message": "Logging started."})
    except Exception as exc:
        return jsonify({"ok": False, "running": False, "message": str(exc)}), 500


@dashboard_bp.route("/api/logging/stop", methods=["POST"])
@login_required
def logging_stop():
    global _logger_process
    _require_csrf()

    role = getattr(current_user, "role_key", "viewer")
    if role not in ("operator", "admin"):
        return jsonify({"ok": False, "running": True, "message": "Operator or admin role required."}), 403

    if _logger_process and _logger_process.poll() is None:
        _logger_process.terminate()
        try:
            _logger_process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            _logger_process.kill()
    _logger_process = None
    return jsonify({"ok": True, "running": False, "message": "Logging stopped."})
