import logging
import json
import re
import serial
from serial import SerialException
from threading import RLock

_telemetry_started = False
_serial_lock = RLock()
_serial_port: serial.Serial | None = None


def send_serial_command(cmd: str) -> bool:
    """Write a newline-terminated command to the open serial port. Returns True on success."""
    import logging
    log = logging.getLogger(__name__)
    with _serial_lock:
        if _serial_port is None or not _serial_port.is_open:
            log.warning("send_serial_command: port not open (port=%s)", _serial_port)
            return False
        try:
            _serial_port.write(f"{cmd}\n".encode())
            _serial_port.flush()
            log.warning("send_serial_command: sent %r to %s", cmd, _serial_port.port)
            return True
        except Exception as exc:
            log.warning("send_serial_command: write failed: %s", exc)
            return False


def start_telemetry(socketio, app):
    global _telemetry_started
    if _telemetry_started:
        return
    _telemetry_started = True
    socketio.start_background_task(_serial_loop, socketio, app)


def _has_valid_readings(data: dict) -> bool:
    """Return True if the packet contains any meaningful sensor reading.

    Accepts packets that have a non-zero, non-null temperature OR a non-zero
    fuel pressure so that the dashboard shows sensors online as long as the
    microcontroller is actively sending data (even if thermocouples are cold
    or temporarily reading 0).
    """
    check_keys = (
        "intake_temp", "intake", "intake_temp_c",
        "exhaust_temp", "exhaust", "exhaust_temp_c", "temp", "chamber_temp",
        "fuel_pressure", "pressure", "rpm",
    )
    for key in check_keys:
        val = data.get(key)
        if val is not None:
            try:
                if float(val) != 0.0:
                    return True
            except (TypeError, ValueError):
                pass
    return False


def _serial_loop(socketio, app):
    global _serial_port
    logger = logging.getLogger(__name__)
    port = app.config.get("SERIAL_PORT", "/dev/ttyUSB0")
    baud = app.config.get("SERIAL_BAUD", 115200)
    timeout = app.config.get("SERIAL_TIMEOUT", 1)
    reconnect_delay = app.config.get("SERIAL_RECONNECT_DELAY", 2)

    ser = None
    buffer = ""
    text_payload = {}
    while True:
        if ser is None or not ser.is_open:
            try:
                # Set DTR/RTS before open to prevent the line toggle that
                # resets ESP32/Arduino on serial connect.
                ser = serial.Serial()
                ser.port = port
                ser.baudrate = baud
                ser.timeout = timeout
                ser.dtr = False
                ser.rts = False
                ser.open()
                with _serial_lock:
                    _serial_port = ser
                logger.info("Telemetry serial connected: %s @ %s", port, baud)
            except SerialException as exc:
                logger.warning("Telemetry serial connect failed: %s", exc)
                socketio.sleep(reconnect_delay)
                continue

        try:
            raw_line = ser.readline().decode("utf-8", errors="ignore")
            # Some USB serial adapters/firmware streams include NUL padding.
            line = raw_line.replace("\x00", "").strip()
        except SerialException as exc:
            logger.warning("Telemetry serial read failed: %s", exc)
            try:
                ser.close()
            except Exception:
                pass
            with _serial_lock:
                _serial_port = None
            ser = None
            socketio.sleep(reconnect_delay)
            continue

        if not line:
            socketio.sleep(0)
            continue

        if "{" in line or "}" in line or buffer:
            buffer += line
            emitted_json = False
            while True:
                start = buffer.find("{")
                if start == -1:
                    if len(buffer) > 2048:
                        buffer = ""
                    break
                if start > 0:
                    buffer = buffer[start:]

                end = buffer.find("}")
                if end == -1:
                    if len(buffer) > 2048:
                        buffer = buffer[-1024:]
                    break

                chunk = buffer[: end + 1]
                buffer = buffer[end + 1 :]
                try:
                    # ESP32 firmware can emit bare `nan`/`inf` which isn't
                    # valid JSON — replace them with null before parsing.
                    safe = re.sub(r'\bnan\b', 'null', chunk, flags=re.IGNORECASE)
                    safe = re.sub(r'\binf\b', 'null', safe, flags=re.IGNORECASE)
                    data = json.loads(safe)
                except json.JSONDecodeError:
                    logger.debug("Telemetry JSON parse failed: %s", chunk)
                    continue
                try:
                    from app.control_approval import update_latest_telemetry

                    update_latest_telemetry(data)
                except Exception:
                    pass
                logger.info("Telemetry parsed from JSON payload: %s", data)
                if _has_valid_readings(data):
                    socketio.emit("sensor_update", data)
                emitted_json = True

            if emitted_json:
                continue

        matched = _parse_text_line(line, text_payload)
        if not matched:
            continue

        required = ("intake_temp", "exhaust_temp", "fuel_pressure", "rpm")
        if all(key in text_payload for key in required):
            # Emit the same keys the dashboard already listens for.
            # [RPM] arrives after [FUEL PRESSURE] in the ESP32 output, so
            # waiting for it ensures all fields are present before emitting.
            payload = {
                "intake_temp": text_payload["intake_temp"],
                "exhaust_temp": text_payload["exhaust_temp"],
                "fuel_pressure": text_payload["fuel_pressure"],
                "pressure": text_payload["fuel_pressure"],
                "temp": text_payload["exhaust_temp"],
                "rpm": text_payload["rpm"],
            }
            for opt_key in ("fuel_valve", "ignition"):
                if opt_key in text_payload:
                    payload[opt_key] = text_payload[opt_key]
            try:
                from app.control_approval import update_latest_telemetry

                update_latest_telemetry(payload)
            except Exception:
                pass
            logger.warning("Telemetry parsed from text payload: %s", payload)
            if _has_valid_readings(payload):
                socketio.emit("sensor_update", payload)
            text_payload.clear()


def _parse_text_line(line, payload):
    line = line.strip()
    # Numeric fields: [LABEL]  <number>
    numeric_patterns = {
        "intake_temp":  r"^\[INTAKE TEMP\]\s+([-+]?\d+(\.\d+)?)\s+C$",
        "exhaust_temp": r"^\[EXHAUST TEMP\]\s+([-+]?\d+(\.\d+)?)\s+C$",
        "fuel_pressure": r"^\[FUEL PRESSURE\]\s+([-+]?\d+(\.\d+)?)\s+PSI$",
        "rpm":          r"^\[RPM\]\s+([-+]?\d+(\.\d+)?)$",
    }
    for key, pattern in numeric_patterns.items():
        match = re.match(pattern, line)
        if match:
            payload[key] = float(match.group(1))
            return True
    # String fields
    string_patterns = {
        "fuel_valve": r"^\[FUEL VALVE\]\s+(\S+)$",
        "ignition":   r"^\[IGNITION\]\s+(\S+)$",
    }
    for key, pattern in string_patterns.items():
        match = re.match(pattern, line)
        if match:
            payload[key] = match.group(1)
            return True
    return False
