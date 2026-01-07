# Changelog
All major changes to this project are recorded here.

---

## [1.4.0] – 2025-01-06
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
