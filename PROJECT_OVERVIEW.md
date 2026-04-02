# Jet Dashboard Project Overview

## What This Project Is
This is a Flask + Socket.IO web application for operating and monitoring a propulsion dashboard.

Core capabilities:
- User authentication with optional TOTP 2FA and CAPTCHA.
- Role-based access (`viewer`, `operator`, `admin`).
- Real-time telemetry display (serial -> Socket.IO -> dashboard).
- Control approval workflow (operator requests, admin approves/rejects).
- Admin panel for users, logs, system actions, and diagnostics.
- Optional live logger process that writes telemetry/control snapshots to PostgreSQL.

## Tech Stack
- Python 3 (venv in `venv/`)
- Flask, Flask-Login, Flask-SQLAlchemy, Flask-Session
- Flask-SocketIO with `gevent` / `gevent-websocket`
- Gunicorn (production)
- PostgreSQL (application DB)
- Serial telemetry via `pyserial`

Main dependencies are listed in `requirements.txt`.

## High-Level Architecture
1. `wsgi.py` creates the app and applies gevent monkey-patching.
2. `app/__init__.py` builds app config, initializes extensions, registers blueprints, and starts telemetry/control background tasks.
3. `app/telemetry.py` reads serial data and emits `sensor_update` Socket.IO events.
4. `app/control_approval.py` manages control state + approval flow and emits control-related Socket.IO events.
5. Frontend dashboard (`app/templates/dashboard.html`) subscribes to telemetry/control events and renders live status.

## Key Files
- `wsgi.py`: WSGI entrypoint and Socket.IO run target.
- `app/__init__.py`: App factory, extension init, blueprint registration.
- `app/telemetry.py`: Serial ingestion and telemetry event emission.
- `app/control_approval.py`: Approval logic and control state machine.
- `app/dashboard.py`: Dashboard routes + logger process control endpoints.
- `app/auth.py`: Login/logout/register/reset + 2FA/CAPTCHA flow.
- `app/admin.py`: Admin routes for users/system diagnostics/actions.
- `app/routes/settings.py`: User settings + 2FA setup/disable.
- `app/templates/`: UI templates (dashboard/admin/auth pages).
- `app/static/`: JS/CSS/assets.

## How It Runs

### Runtime Modes
- **Development/manual run**: start with Python/Socket.IO directly.
- **Production**: managed by systemd service running Gunicorn with gevent websocket worker.

### Local Manual Run
From `/opt/jet_dashboard`:

```bash
source venv/bin/activate
pip install -r requirements.txt
python wsgi.py
```

App binds to:
- `http://0.0.0.0:8080`

### Production Service (systemd)
Service file:
- `/etc/systemd/system/propulsion-dashboard.service`

Current production command:
- Gunicorn with `geventwebsocket.gunicorn.workers.GeventWebSocketWorker`
- Binds `0.0.0.0:8080`
- Working directory `/opt/jet_dashboard`

Useful commands:

```bash
sudo systemctl status propulsion-dashboard --no-pager
sudo systemctl restart propulsion-dashboard
journalctl -u propulsion-dashboard -n 120 --no-pager
```

## Environment Configuration
Primary env file:
- `.env` in project root

Important variables (set values appropriate for your environment):
- Database: `DATABASE_URL`, `DB_NAME`, `DB_USER`, `DB_PASS`, `DB_HOST`, `DB_PORT`
- Security/session: `SECRET_KEY`, `SESSION_TIMEOUT_SECONDS`
- CAPTCHA: `RECAPTCHA_SITE_KEY`, `RECAPTCHA_SECRET_KEY`
- SMTP/email: `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`
- Telemetry: `TELEMETRY_ENABLED`, `SERIAL_PORT`, `SERIAL_BAUD`, `SERIAL_TIMEOUT`, `SERIAL_RECONNECT_DELAY`
- Logger auth: `LOGGER_SECRET`

## Telemetry Data Flow
1. ESP/serial device writes telemetry to configured serial port.
2. `app/telemetry.py` reads serial lines and parses:
   - JSON payloads, or
   - text-formatted telemetry lines.
3. Parsed payload emits via Socket.IO event:
   - `sensor_update`
4. Dashboard frontend updates intake/exhaust/pressure/rpm indicators from event payload.

## Control Approval Flow
1. Operator attempts privileged action (e.g. `fuel_open`, `spark_on`).
2. System creates pending request and notifies admin sockets.
3. Admin approves/rejects via Socket.IO actions.
4. State updates broadcast through:
   - `control_state_update`
   - `approval_request`
   - `approval_cleared`
   - `control_notice`

## Data + Sessions
- SQLAlchemy models under `app/models/`.
- Session storage configured as filesystem (`flask_session/`).
- `db.create_all()` is called during startup in app context.

## Operational Notes
- Service stop/restart can take up to `TimeoutStopSec=30` before force kill.
- Serial telemetry availability is strongly dependent on:
  - correct `SERIAL_PORT` path,
  - device availability,
  - valid frame format from firmware.

## Quick Troubleshooting
- App up check:
  - `curl http://127.0.0.1:8080/status`
- Service logs:
  - `journalctl -u propulsion-dashboard -n 120 --no-pager`
- Serial ownership:
  - `sudo lsof /dev/ttyUSB0`
- If telemetry is stale/missing:
  - verify serial device path in service file,
  - verify firmware output format,
  - verify `sensor_update` payload keys expected by dashboard.

## Suggested Repo Entry Read Order
1. `wsgi.py`
2. `app/__init__.py`
3. `app/telemetry.py`
4. `app/control_approval.py`
5. `app/dashboard.py`
6. `app/auth.py`
7. `app/admin.py`

