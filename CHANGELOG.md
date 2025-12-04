# Changelog
All major changes to this project are recorded here.

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
