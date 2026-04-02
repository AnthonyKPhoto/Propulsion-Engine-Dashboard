# Changelog
All major changes to this project are recorded here.

---

## [1.5.0] – 2026-04-02
### Added
- Real-time Operator → Admin control approval workflow (`app/control_approval.py`):
  - Operators request dangerous actions (fuel open, spark on) via SocketIO.
  - Admin receives a live approval prompt; must confirm within 15 seconds.
  - Timeout automatically triggers emergency stop if no admin response.
  - Telemetry watchdog: declares a fault if no sensor data arrives within 5 seconds.
- Serial command output: fuel valve toggle now writes `OPEN\n` / `CLOSE\n` directly
  to the ESP32 receiver over serial (`/dev/ttyUSB0` at 115200 baud).
- Telemetry serial reader extracted into `app/telemetry.py` as a dedicated background
  gevent task with automatic reconnect.
- Engine log API (`app/routes/logs.py`): paginated JSON endpoint plus CSV and JSON
  download for the `engine_log` table.
- Logger simulator script (`app/logger.py`) for inserting synthetic engine telemetry
  into the database during development.
- Alarm threshold API (`/dashboard/api/alarm/set`): configurable exhaust temperature
  alarm with armed/triggered status broadcast over SocketIO.
- Logger process control API (`/dashboard/api/logging/start|stop|status`) allowing
  admins and operators to start and stop the logger subprocess from the dashboard.
- System update UI in the admin panel with live progress streaming.
- Favicon and default user profile image added to static assets.
- `.env.example` template for environment variable documentation.

### Changed
- Serial port open sequence fixed: DTR and RTS are now set to `False` before the port
  opens, preventing the line toggle that was resetting the ESP32 receiver on every
  connect.
- Serial text-line parser updated to match actual ESP32 output format
  (`[INTAKE TEMP]`, `[EXHAUST TEMP]`, `[FUEL PRESSURE]`, `[FUEL VALVE]`,
  `[IGNITION]`, `[RPM]`) replacing the old `Intake Temp (C):` patterns.
- Dashboard now displays Axle RPM and Fuel Pressure with live SocketIO updates and
  "Sensor offline" indicators when data stops arriving.
- `monitoring.html` removed; monitoring content consolidated into the main dashboard.
- Root-level `logger.py` moved to `app/logger.py`.
- `wsgi.py` updated to call `gevent.monkey.patch_all()` before app creation for
  correct gevent/SocketIO compatibility.
- Admin user list and system pages expanded with additional controls and layout
  improvements.
- Log page chart (`app/static/js/logs.js`) updated with improved rendering and
  data handling.
- Profile images removed from git tracking; `app/static/profiles/*` added to
  `.gitignore` to prevent PII being committed.
- `.gitignore` extended to cover `.claude/`, `*.zip`, `.DS_Store`, and build
  artifacts.

### Fixed
- Emergency stop now correctly locks out all further control actions until cleared.
- CSRF validation applied consistently across all new POST control endpoints.

---

## [1.4.0] – 2026-01-06
### Added
- 3-tier RBAC (Viewer / Operator / Admin) with normalized roles and updated role badges.
- Authentication and authorization audit logging for:
  - Login / logout
  - Registration
  - Password changes and resets
  - 2FA enable / disable
  - Settings and profile updates
  - Admin verification actions
- “Commanded vs Actual” state indicators for ignition, fuel, starter, and fan.
- Emergency Stop banner with control lockout and clear **FAULT** status indication.
- Alarm status badges (Armed / Triggered).
- Telemetry offline indicators using `--` placeholders.
- Fan preset active-mode highlighting.
- Restyled **Request Access** page to match site UI, including CSRF token support.

### Changed
- Monitoring controls restricted to Operator and Admin roles; Viewers receive explicit permission-denied messaging.
- Role changes restricted to Admin only (UI and server-side enforcement).
- Settings and profile pages restricted to Admin only.
- Hardened session handling with idle timeout and secure cookie settings.
- Control order updated (Starter → Fuel → Ignition) with improved label and button spacing.
- Fuel Pressure label and value layout aligned with other telemetry rows.

### Fixed
- Viewer permissions now fully block all dashboard control interactions with a clear alert message.

---

## [1.3.0] – 2025-02-16
### Added
- Monitoring page concept for quick-view runtime metrics.
- Expanded guide for GitHub setup, deployment, and configuration.
- Documentation for collaborators and project hardware setup.

### Changed
- Updated README and installation guide for Raspberry Pi and production deployment.
- Refined admin panel documentation and telemetry setup instructions.

---

## [1.2.0] – 2025-01-10
### Added
- Event logging system (`event_logs` table).
- Backup & restore interface using PostgreSQL tools.
- Admin panel enhancements.

### Changed
- Improved authentication and role-based access around control routes.
- Upgraded UI templates and theme handling for dashboard and admin.

### Fixed
- Issues with serial disconnection handling.
- CSRF protection inconsistencies in control routes.

---

## [1.1.0] – 2024-12-20
### Added
- Admin panel framework.
- User preferences: light/dark theme, accent color, Celsius/Fahrenheit toggle.
- Fundamental database structure for `users` and basic telemetry.

### Changed
- Restructured templates into `dashboard/`, `admin/`, and `auth/`.
- Cleaned up layout, navigation, and session flows.

---

## [1.0.0] – 2024-12-03
### Initial Release
- Flask app scaffold created.
- Basic dashboard UI.
- Serial telemetry reader first implemented.
- Simple user login system.
- Repo created and pushed to GitHub.

---

[1.3.0]: https://github.com/AnthonyKPhoto/Propulsion-Engine-Dashboard
