# app/dashboard.py

from datetime import datetime, timedelta
import random
import string
from typing import Dict, List, Tuple

from flask import Blueprint, render_template, jsonify, request, abort
from flask_login import login_required, current_user
from flask_wtf.csrf import generate_csrf, validate_csrf
from wtforms.validators import ValidationError

from app import db, limiter
from app.models.event_log import EventLog

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/dashboard")


# ----- MAIN DASHBOARD -----
@dashboard_bp.route("/")
@login_required
def dashboard():
    """
    Legacy dashboard view.
    theme/accent/role are injected globally from app context processor.
    """
    return render_template("dashboard.html")


@dashboard_bp.route("/monitoring")
@login_required
def monitoring():
    """
    Monitoring/operations view (new tab).
    """
    return render_template("monitoring.html", csrf_token=generate_csrf())


# ----- LOGS PAGE -----
@dashboard_bp.route("/logs")
@login_required
def logs():
    return render_template("logs.html")


# ----- SETTINGS REDIRECT -----
# The real settings page is now handled by settings_bp (/dashboard/settings)
@dashboard_bp.route("/settings")
@login_required
def settings_redirect():
    return render_template("settings.html")


# --- Monitoring simulation + helpers ---------------------------------
# The live links to ESP/Pi/Teensy can be wired into the update points below.
# Until then we run a lightweight simulator so the UI has shape + data.

TrendBuffer = List[Tuple[float, float]]

monitoring_state: Dict = {
    "engine_status": "idle",  # idle, preignite, ignition, cooldown, fault
    "mode": "Idle",
    "connections": {"esp32": True, "pi_sensors": True, "teensy": True},
    "safety_lock": False,
    "log_file": "run-{:%Y%m%d-%H%M%S}.log".format(datetime.utcnow()),
    "controls": {
        "ignition_enabled": False,
        "fuel_valve_open": False,
        "edf_power": 18,
        "logging_enabled": True,
    },
    "metadata": {
        "test_id": "TST-" + "".join(random.choices(string.ascii_uppercase, k=4)),
        "operator": "Unknown",
        "engine_mode": "Idle",
        "auto_shutdown": {
            "temp": 1150,
            "pressure_drop": 18,
            "rpm": 58000,
            "voltage": 20,
        },
    },
    "last_sample": datetime.utcnow(),
    "trends": {
        "chamber_temp": [],  # °C
        "fuel_pressure": [],  # PSI
        "rpm": [],
        "voltage": [],
        "current": [],
    },
    "alerts": [],
}

THRESHOLDS = {
    "chamber_temp": {"warn": 980, "danger": 1100},
    "exhaust_temp": {"warn": 720, "danger": 850},
    "intake_temp": {"warn": 120, "danger": 160},
    "fuel_pressure": {"warn": 28, "danger": 20},
    "rpm": {"warn": 48000, "danger": 56000},
    "voltage": {"warn": 21, "danger": 20},
    "current": {"warn": 70, "danger": 85},
}


def _log_event(message: str, category: str = "monitor"):
    entry = EventLog(message=message[:255], category=category[:64])
    db.session.add(entry)
    db.session.commit()


def _status_for(metric: str, value: float) -> str:
    limits = THRESHOLDS.get(metric)
    if not limits:
        return "normal"
    if metric == "fuel_pressure":
        if value <= limits["danger"]:
            return "danger"
        if value <= limits["warn"]:
            return "warning"
    else:
        if value >= limits["danger"]:
            return "danger"
        if value >= limits["warn"]:
            return "warning"
    return "normal"


def _append_trend(key: str, value: float):
    buffer: TrendBuffer = monitoring_state["trends"].setdefault(key, [])
    buffer.append((datetime.utcnow().timestamp(), round(value, 2)))
    # keep 90 points (~45s @ 0.5s) to let the client trim to 30s
    if len(buffer) > 90:
        del buffer[: len(buffer) - 90]


def _simulate_step():
    """
    Lightweight synthesizer for demo/empty backends.
    Replace with real sensor polling in production.
    """
    status = monitoring_state["engine_status"]
    base_temp = {"idle": 420, "preignite": 760, "ignition": 990, "cooldown": 520, "fault": 600}.get(status, 420)
    chamber_temp = max(320, random.gauss(base_temp, 14))
    exhaust_temp = max(260, chamber_temp - random.uniform(140, 210))
    intake_temp = max(22, random.gauss(65, 6))
    fuel_pressure = max(12, random.gauss(38, 3.2))
    rpm = max(8000, random.gauss(42000 + monitoring_state["controls"]["edf_power"] * 350, 2500))
    voltage = max(18.4, random.gauss(24.6, 0.35))
    current = max(8, random.gauss(54 + monitoring_state["controls"]["edf_power"] * 0.6, 5))

    metrics = {
        "chamber_temp": chamber_temp,
        "exhaust_temp": exhaust_temp,
        "intake_temp": intake_temp,
        "fuel_pressure": fuel_pressure,
        "fuel_flow": round(max(0.1, monitoring_state["controls"]["fuel_valve_open"]) * 24.5, 2),
        "rpm": rpm,
        "voltage": voltage,
        "current": current,
    }

    for key in ("chamber_temp", "fuel_pressure", "rpm", "voltage", "current"):
        _append_trend(key, metrics[key])

    _update_alerts(metrics)
    monitoring_state["last_metrics"] = metrics
    return metrics


def _update_alerts(metrics: Dict[str, float]):
    now_ts = datetime.utcnow().timestamp()

    def add_alert(text: str, severity: str):
        monitoring_state["alerts"].append(
            {
                "id": f"{int(now_ts*1000)}-{len(monitoring_state['alerts'])}",
                "text": text,
                "severity": severity,
                "ts": now_ts,
            }
        )

    # clear stale (>60s) alerts
    monitoring_state["alerts"] = [
        a for a in monitoring_state["alerts"] if now_ts - a.get("ts", now_ts) <= 60
    ]

    if metrics["fuel_pressure"] <= THRESHOLDS["fuel_pressure"]["danger"]:
        add_alert("Low fuel pressure", "danger")
    elif metrics["fuel_pressure"] <= THRESHOLDS["fuel_pressure"]["warn"]:
        add_alert("Fuel pressure dropping", "warning")

    if metrics["chamber_temp"] >= THRESHOLDS["chamber_temp"]["danger"]:
        add_alert("Chamber temperature critical", "danger")
    elif metrics["chamber_temp"] >= THRESHOLDS["chamber_temp"]["warn"]:
        add_alert("Chamber temperature rising fast", "warning")

    if metrics["rpm"] >= THRESHOLDS["rpm"]["danger"]:
        add_alert("RPM overshoot detected", "danger")
    elif metrics["rpm"] >= THRESHOLDS["rpm"]["warn"]:
        add_alert("RPM near limit", "warning")


def _advance_simulation():
    now = datetime.utcnow()
    if (now - monitoring_state["last_sample"]).total_seconds() < 0.2:
        return
    monitoring_state["last_sample"] = now
    return _simulate_step()


def _require_csrf():
    token = request.headers.get("X-CSRFToken") or request.form.get("csrf_token")
    if not token:
        abort(400, description="Missing CSRF token.")
    try:
        validate_csrf(token)
    except ValidationError as exc:  # type: ignore
        abort(400, description=f"Invalid CSRF token: {exc}")


def _guard_admin_controls():
    if not current_user.is_authenticated:
        abort(401)
    if not current_user.is_admin():
        abort(403, description="Administrator role required for control actions.")


@dashboard_bp.route("/api/monitoring/snapshot")
@login_required
def monitoring_snapshot():
    _advance_simulation()
    metrics = monitoring_state.get("last_metrics") or _simulate_step()
    monitoring_state["metadata"]["operator"] = getattr(current_user, "username", "Unknown")
    monitoring_state["metadata"]["engine_mode"] = monitoring_state["mode"]

    return jsonify(
        {
            "timestamp": datetime.utcnow().isoformat(),
            "engine": {
                "status": monitoring_state["engine_status"],
                "mode": monitoring_state["mode"],
                "safety_lock": monitoring_state["safety_lock"],
            },
            "connections": monitoring_state["connections"],
            "metrics": metrics,
            "metric_states": {
                "chamber_temp": _status_for("chamber_temp", metrics["chamber_temp"]),
                "exhaust_temp": _status_for("exhaust_temp", metrics["exhaust_temp"]),
                "intake_temp": _status_for("intake_temp", metrics["intake_temp"]),
                "fuel_pressure": _status_for("fuel_pressure", metrics["fuel_pressure"]),
                "rpm": _status_for("rpm", metrics["rpm"]),
                "voltage": _status_for("voltage", metrics["voltage"]),
                "current": _status_for("current", metrics["current"]),
            },
            "controls": monitoring_state["controls"],
            "log_file": monitoring_state["log_file"],
            "alerts": monitoring_state["alerts"][-12:],
            "metadata": monitoring_state["metadata"],
            "trends": monitoring_state["trends"],
        }
    )


@dashboard_bp.route("/api/monitoring/control", methods=["POST"])
@login_required
@limiter.limit("30/minute")
def monitoring_control():
    _require_csrf()
    _guard_admin_controls()

    payload = request.get_json() or {}
    action = payload.get("action")
    value = payload.get("value")

    if monitoring_state.get("safety_lock") and action != "clear_fault":
        abort(409, description="Engine is in safety lock; clear fault before issuing commands.")

    message = None

    if action == "toggle_ignition":
        flag = bool(value)
        monitoring_state["controls"]["ignition_enabled"] = flag
        monitoring_state["engine_status"] = "preignite" if flag else "idle"
        monitoring_state["mode"] = "Pre-Ignite" if flag else "Idle"
        message = f"Ignition {'ENABLED' if flag else 'DISABLED'}"

    elif action == "toggle_fuel_valve":
        flag = bool(value)
        monitoring_state["controls"]["fuel_valve_open"] = flag
        message = f"Fuel valve {'OPEN' if flag else 'CLOSED'}"

    elif action == "set_edf_power":
        try:
            pct = max(0, min(100, int(value)))
        except (TypeError, ValueError):
            abort(400, description="EDF power must be 0-100.")
        monitoring_state["controls"]["edf_power"] = pct
        monitoring_state["mode"] = "Ignition" if pct >= 50 else monitoring_state["mode"]
        message = f"EDF/Compressor power set to {pct}%"

    elif action == "set_logging":
        flag = bool(value)
        monitoring_state["controls"]["logging_enabled"] = flag
        if flag:
            monitoring_state["log_file"] = "run-{:%Y%m%d-%H%M%S}.log".format(datetime.utcnow())
        message = f"Logging {'STARTED' if flag else 'STOPPED'} -> {monitoring_state['log_file']}"

    elif action == "emergency_shutdown":
        monitoring_state["engine_status"] = "fault"
        monitoring_state["mode"] = "Shutdown"
        monitoring_state["controls"]["ignition_enabled"] = False
        monitoring_state["controls"]["fuel_valve_open"] = False
        monitoring_state["controls"]["edf_power"] = 0
        monitoring_state["safety_lock"] = True
        message = "EMERGENCY SHUTDOWN triggered"

    elif action == "clear_fault":
        monitoring_state["safety_lock"] = False
        monitoring_state["engine_status"] = "idle"
        monitoring_state["mode"] = "Idle"
        message = "Safety lock cleared; engine back to idle"

    else:
        abort(400, description="Unknown control action.")

    if message:
        _log_event(f"{current_user.username}: {message}", category="control")

    return jsonify({"ok": True, "message": message})
