from __future__ import annotations

import os
from datetime import datetime, timedelta
from threading import RLock
from uuid import uuid4

from flask import request
from flask_login import current_user
from flask_socketio import SocketIO, emit, join_room

from app import db
from app.models.event_log import EventLog

APPROVAL_TIMEOUT_SECONDS = 15
TELEMETRY_FAULT_SECONDS = 5  # seconds without data before declaring a fault

_lock = RLock()
_socketio: SocketIO | None = None
_timeout_worker_started = False
_telemetry_watchdog_started = False
_admin_sids: set[str] = set()
_sid_user: dict[str, dict] = {}

_last_telemetry_ts: datetime | None = None
_telemetry_fault = False

_alarm_threshold: float = 0.0
_alarm_triggered: bool = False
_latest_temp: float | None = None

_state = {
    "fuel_open": False,
    "spark_on": False,
    "emergency_stop": False,
    "pending_request": None,
    "latest_rpm": 0.0,
}


def register_control_socketio_handlers(socketio: SocketIO):
    global _socketio, _timeout_worker_started, _telemetry_watchdog_started
    _socketio = socketio
    if not _timeout_worker_started:
        _timeout_worker_started = True
        socketio.start_background_task(_approval_timeout_worker)
    if not _telemetry_watchdog_started:
        _telemetry_watchdog_started = True
        socketio.start_background_task(_telemetry_watchdog)

    @socketio.on("connect")
    def _on_connect(auth=None):
        sid = request.sid

        # Allow the logger service to connect using a shared secret.
        logger_secret = os.getenv("LOGGER_SECRET")
        if logger_secret and isinstance(auth, dict) and auth.get("token") == logger_secret:
            with _lock:
                _sid_user[sid] = {"id": None, "username": "__logger__", "role": "logger"}
                state_payload = _state_payload_locked()
            emit("control_state_update", state_payload, to=sid)
            return

        if not current_user.is_authenticated:
            return False

        role = getattr(current_user, "role_key", "viewer")
        with _lock:
            _sid_user[sid] = {
                "id": current_user.id,
                "username": current_user.username,
                "role": role,
            }
            if role == "admin":
                _admin_sids.add(sid)
                join_room("admins")

            state_payload = _state_payload_locked()
            pending = _pending_payload_locked()
            alarm_payload = _alarm_payload_locked()

        emit("control_state_update", state_payload, to=sid)
        if pending and role == "admin":
            emit("approval_request", pending, to=sid)
        emit("alarm_state", alarm_payload, to=sid)
        _broadcast_admin_presence()

    @socketio.on("disconnect")
    def _on_disconnect():
        sid = request.sid
        with _lock:
            _sid_user.pop(sid, None)
            _admin_sids.discard(sid)
        _broadcast_admin_presence()


def update_latest_telemetry(data: dict):
    global _last_telemetry_ts, _telemetry_fault, _latest_temp

    rpm = data.get("rpm")
    if rpm is not None:
        try:
            rpm = float(rpm)
        except (TypeError, ValueError):
            pass
        else:
            with _lock:
                _state["latest_rpm"] = rpm

    # Extract the temperature value the dashboard uses for the alarm display.
    temp_raw = (data.get("temp") or data.get("chamber_temp") or
                data.get("exhaust_temp") or data.get("exhaust") or
                data.get("exhaust_temp_c"))

    recovery = False
    alarm_payload = None
    with _lock:
        _last_telemetry_ts = datetime.utcnow()
        if _telemetry_fault:
            _telemetry_fault = False
            recovery = True
            _log_control("TELEMETRY RECOVERY sensor data restored", "telemetry")

        if temp_raw is not None:
            try:
                temp_val = float(temp_raw)
                if temp_val != 0.0:
                    _latest_temp = temp_val
                    if _check_alarm_locked(temp_val):
                        alarm_payload = _alarm_payload_locked()
            except (TypeError, ValueError):
                pass

    if recovery:
        _emit("control_notice", {"level": "success", "message": "Telemetry signal restored."})
    if alarm_payload is not None:
        _emit("alarm_state", alarm_payload)


def handle_control_action(user, action: str, request_id: str | None = None):
    role = getattr(user, "role_key", "viewer")
    if role not in ("operator", "admin"):
        return _response(False, "User permissions not met.", 403)

    with _lock:
        if action in ("approve_request", "reject_request"):
            if role != "admin":
                return _response(False, "Administrator role required.", 403)
            return _handle_admin_decision_locked(user.username, action, request_id)

        if action in ("fuel_open", "spark_on") and role != "admin":
            return _handle_operator_request_locked(user, action)

        return _execute_direct_action_locked(action, actor=user.username, actor_role=role)


def current_state():
    with _lock:
        return _state_payload_locked()


def _handle_operator_request_locked(user, action: str):
    if _state["pending_request"]:
        return _response(False, "Another approval request is already pending.", 409)
    if _state["emergency_stop"]:
        return _response(False, "System is in emergency stop. Reset required.", 409)
    if len(_admin_sids) == 0:
        _log_control(
            f"CONTROL REQUEST DENIED no_admin_online action={action} operator={user.username}",
            "control",
        )
        return _response(False, "No admin is online for approval.", 409)
    precheck = _precheck_action_locked(action)
    if precheck:
        return _response(False, precheck, 409)

    req_id = str(uuid4())
    expires_at = datetime.utcnow() + timedelta(seconds=APPROVAL_TIMEOUT_SECONDS)
    pending = {
        "id": req_id,
        "action": action,
        "operator": user.username,
        "operator_id": user.id,
        "created_at": datetime.utcnow().isoformat() + "Z",
        "expires_at": expires_at.isoformat() + "Z",
    }
    _state["pending_request"] = pending
    _log_control(
        f"CONTROL REQUEST CREATED action={action} operator={user.username} request_id={req_id}",
        "control",
    )
    _emit("approval_request", _pending_payload_locked(), room="admins")
    _emit(
        "control_notice",
        {"level": "info", "message": f"Approval requested for {action.replace('_', ' ')}."},
    )
    return _response(
        True,
        "Approval requested.",
        202,
        pending=True,
        request=_pending_payload_locked(),
        state=_state_payload_locked(),
    )


def _handle_admin_decision_locked(admin_username: str, action: str, request_id: str | None):
    pending = _state["pending_request"]
    if not pending:
        return _response(False, "No pending approval request.", 409)
    if request_id and request_id != pending["id"]:
        return _response(False, "Approval request no longer valid.", 409)

    if action == "reject_request":
        _log_control(
            f"CONTROL REQUEST REJECTED request_id={pending['id']} action={pending['action']} operator={pending['operator']} admin={admin_username}",
            "control",
        )
        _state["pending_request"] = None
        _emit(
            "control_notice",
            {
                "level": "warning",
                "message": f"Request rejected by admin ({pending['action'].replace('_', ' ')}).",
            },
        )
        _emit("approval_cleared", {"id": pending["id"]})
        return _response(True, "Request rejected.", 200, state=_state_payload_locked())

    requested_action = pending["action"]
    _state["pending_request"] = None
    result_body, result_status = _execute_direct_action_locked(
        requested_action,
        actor=admin_username,
        actor_role="admin",
        source="approved",
        operator=pending["operator"],
        request_id=pending["id"],
    )
    if not result_body["ok"]:
        _emit(
            "control_notice",
            {"level": "danger", "message": result_body["message"]},
        )
    _emit("approval_cleared", {"id": pending["id"]})
    return result_body, result_status


def _execute_direct_action_locked(
    action: str,
    actor: str,
    actor_role: str,
    source: str = "direct",
    operator: str | None = None,
    request_id: str | None = None,
):
    if action == "emergency_stop":
        _apply_emergency_stop_locked(reason=f"manual:{actor}")
        _log_control(
            f"CONTROL EMERGENCY_STOP actor={actor} role={actor_role} source={source}",
            "safety",
        )
        _emit("control_notice", {"level": "danger", "message": "Emergency stop activated."})
        _emit("control_state_update", _state_payload_locked())
        return _response(True, "Emergency stop activated.", 200, state=_state_payload_locked())

    if action == "reset_estop":
        global _alarm_triggered
        _state["emergency_stop"] = False
        alarm_cleared = _alarm_triggered
        if alarm_cleared:
            _alarm_triggered = False
        _log_control(f"CONTROL RESET_ESTOP actor={actor} role={actor_role}", "safety")
        _emit("control_notice", {"level": "info", "message": "Emergency stop reset."})
        _emit("control_state_update", _state_payload_locked())
        if alarm_cleared:
            _emit("alarm_state", _alarm_payload_locked())
        return _response(True, "Emergency stop reset.", 200, state=_state_payload_locked())

    if _state["emergency_stop"]:
        return _response(False, "System is in emergency stop. Reset required.", 409)

    precheck = _precheck_action_locked(action)
    if precheck:
        return _response(False, precheck, 409)

    serial_cmd = None
    if action == "fuel_open":
        _state["fuel_open"] = True
        serial_cmd = "OPEN"
    elif action == "fuel_close":
        _state["fuel_open"] = False
        _state["spark_on"] = False
        serial_cmd = "CLOSE"
    elif action == "spark_on":
        _state["spark_on"] = True
    elif action == "spark_off":
        _state["spark_on"] = False
    else:
        return _response(False, "Unknown control action.", 400)

    audit = (
        f"CONTROL ACTION action={action} actor={actor} role={actor_role} source={source} "
        f"operator={operator or '-'} request_id={request_id or '-'} state={_state_payload_locked()['system_state']}"
    )
    _log_control(audit, "control")
    _emit("control_state_update", _state_payload_locked())

    if serial_cmd:
        _send_serial(serial_cmd)

    return _response(True, f"{action.replace('_', ' ').title()} executed.", 200, state=_state_payload_locked())


def _precheck_action_locked(action: str):
    if action == "fuel_open":
        if _state["fuel_open"]:
            return "Fuel valve is already open."
        return None
    if action == "fuel_close":
        if not _state["fuel_open"]:
            return "Fuel valve is already closed."
        return None
    if action == "spark_on":
        if _state["spark_on"]:
            return "Spark plug is already on."
        if not _state["fuel_open"]:
            return "Fuel valve must be open before enabling spark plug."
        if float(_state["latest_rpm"] or 0) <= 0:
            return "Axle RPM must be above zero before enabling spark plug."
        return None
    if action == "spark_off":
        if not _state["spark_on"]:
            return "Spark plug is already off."
        return None
    return None


def set_alarm_threshold(threshold: float):
    """Public API — set alarm threshold and broadcast to all clients."""
    global _alarm_threshold, _alarm_triggered
    alarm_payload = None
    with _lock:
        _alarm_threshold = max(0.0, float(threshold))
        if _alarm_threshold == 0.0:
            _alarm_triggered = False
        elif _latest_temp is not None and _latest_temp != 0.0:
            _check_alarm_locked(_latest_temp)
        alarm_payload = _alarm_payload_locked()
    if alarm_payload is not None:
        _emit("alarm_state", alarm_payload)


def _alarm_payload_locked() -> dict:
    return {
        "threshold": _alarm_threshold,
        "triggered": _alarm_triggered,
        "current_temp": _latest_temp,
    }


def _check_alarm_locked(temp: float) -> bool:
    """Evaluate alarm state against current temp. Returns True if state changed."""
    global _alarm_triggered
    if _alarm_threshold <= 0:
        if _alarm_triggered:
            _alarm_triggered = False
            return True
        return False
    now_triggered = temp >= _alarm_threshold
    if now_triggered == _alarm_triggered:
        return False
    _alarm_triggered = now_triggered
    if now_triggered:
        _log_control(
            f"ALARM TRIGGERED temp={temp:.1f} threshold={_alarm_threshold:.1f}", "safety"
        )
    else:
        _log_control(f"ALARM CLEARED temp={temp:.1f}", "safety")
    return True


def _telemetry_watchdog():
    """Declare a fault and emergency-stop if telemetry goes silent while active."""
    global _telemetry_fault
    while True:
        if _socketio is None:
            return
        _socketio.sleep(1)

        with _lock:
            if _last_telemetry_ts is None:
                # Never received any telemetry yet — nothing to watch.
                continue

            age = (datetime.utcnow() - _last_telemetry_ts).total_seconds()

            if _telemetry_fault or age <= TELEMETRY_FAULT_SECONDS:
                continue

            # New fault: telemetry has gone silent.
            _telemetry_fault = True
            system_state = _system_state_locked()
            _log_control(
                f"TELEMETRY FAULT no data for {age:.1f}s system_state={system_state}",
                "telemetry",
            )

            if system_state in ("ARMED", "RUNNING"):
                _apply_emergency_stop_locked(reason="telemetry_loss")
                _log_control("SAFETY EMERGENCY_STOP reason=telemetry_loss", "safety")
                _emit(
                    "control_notice",
                    {"level": "danger", "message": "Telemetry lost — emergency stop triggered."},
                )
                _emit("control_state_update", _state_payload_locked())
            else:
                _emit(
                    "control_notice",
                    {"level": "warning", "message": "Telemetry signal lost."},
                )


def _approval_timeout_worker():
    while True:
        if _socketio is None:
            return
        with _lock:
            pending = _state["pending_request"]
            if pending:
                exp = datetime.fromisoformat(pending["expires_at"])
                if datetime.utcnow() >= exp:
                    request_id = pending["id"]
                    action = pending["action"]
                    operator = pending["operator"]
                    _state["pending_request"] = None
                    _apply_emergency_stop_locked(reason="approval_timeout")
                    _log_control(
                        f"CONTROL REQUEST TIMEOUT request_id={request_id} action={action} operator={operator} -> EMERGENCY_STOP",
                        "safety",
                    )
                    _emit("approval_cleared", {"id": request_id})
                    _emit(
                        "control_notice",
                        {
                            "level": "danger",
                            "message": "Approval timed out (15s). Emergency stop triggered.",
                        },
                    )
                    _emit("control_state_update", _state_payload_locked())
        _socketio.sleep(0.5)


def _apply_emergency_stop_locked(reason: str):
    _state["fuel_open"] = False
    _state["spark_on"] = False
    _state["emergency_stop"] = True
    _state["pending_request"] = None
    _log_control(f"SAFETY EMERGENCY_STOP reason={reason}", "safety")
    _send_serial("CLOSE")


def _state_payload_locked():
    return {
        "fuel_open": bool(_state["fuel_open"]),
        "spark_on": bool(_state["spark_on"]),
        "emergency_stop": bool(_state["emergency_stop"]),
        "system_state": _system_state_locked(),
        "latest_rpm": float(_state["latest_rpm"] or 0),
        "pending_request": _pending_payload_locked(),
    }


def _pending_payload_locked():
    pending = _state["pending_request"]
    if not pending:
        return None
    return {
        "id": pending["id"],
        "action": pending["action"],
        "operator": pending["operator"],
        "created_at": pending["created_at"],
        "expires_at": pending["expires_at"],
        "timeout_seconds": APPROVAL_TIMEOUT_SECONDS,
    }


def _system_state_locked():
    if _state["emergency_stop"]:
        return "FAULT"
    if _state["spark_on"]:
        return "RUNNING"
    if _state["fuel_open"]:
        return "ARMED"
    return "IDLE"


def _response(ok: bool, message: str, status: int, **extra):
    body = {"ok": ok, "message": message}
    body.update(extra)
    return body, status


def _emit(event: str, payload: dict, room: str | None = None):
    if _socketio is None:
        return
    if room:
        _socketio.emit(event, payload, room=room)
    else:
        _socketio.emit(event, payload)


def _broadcast_admin_presence():
    _emit("admin_presence", {"online": len(_admin_sids) > 0, "count": len(_admin_sids)})


def _send_serial(cmd: str):
    import logging
    log = logging.getLogger(__name__)
    try:
        from app.telemetry import send_serial_command
        ok = send_serial_command(cmd)
        log.warning("Serial command %r sent=%s", cmd, ok)
    except Exception as exc:
        log.warning("Serial command %r failed: %s", cmd, exc)


def _log_control(message: str, category: str):
    try:
        db.session.add(EventLog(message=message[:255], category=category[:64]))
        db.session.commit()
    except Exception:
        db.session.rollback()
