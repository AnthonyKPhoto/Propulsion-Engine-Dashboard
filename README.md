# Jet Dashboard – Propulsion Test Stand Telemetry & Control

> Senior design project for a small-scale propulsion / jet engine test stand with a secure, web-based dashboard.

Jet Dashboard is a Python/Flask web application that runs on a single-board computer (e.g., Raspberry Pi) and talks to a microcontroller (e.g., ESP32) over serial. It provides real-time telemetry (temperature, pressure, RPM, valve states, etc.) and control for a propulsion test stand, with user authentication, role-based access, and safety-focused controls.

This project is being developed as part of a senior design project at Capitol Technology University.

---
## Collaborators
- **Anthony Kaiser**
- **Rayel Tiomela**
- **Gordon Montrose**
- **Oluwatobi Awobayikun**
- **Newton Devaraj**


---

## Features

- **Real-time telemetry**
  - Live display of key metrics from the propulsion test stand (e.g., temps, pressures, RPM, valve states).
  - Auto-refreshing dashboard with compact “quick view” status cards.
  - Historical views via event logs (depending on DB configuration).

- **Control interface**
  - Control panel for arming, disarming, and issuing commands to the test stand.
  - Separation between **monitoring-only** and **control** interfaces.
  - Control routes protected by authentication, roles, and CSRF protection.

- **Secure user authentication**
  - Login system with username + password.
  - Password hashing using Werkzeug’s password hash utilities.
  - Role-based access control (e.g., `admin`, `user`).
  - CSRF protection for forms (Flask-WTF).
  - HTTPS and security headers enforced in production via Flask-Talisman / reverse proxy configuration.

- **Admin panel**
  - User management (create, approve, disable users) – depending on current implementation.
  - System control cards (start/stop services, restart telemetry, backup/restore DB).
  - Telemetry configuration and view of recent events / logs.

- **Event logging**
  - Database-backed `event_logs` table for recording system events (e.g., “Ignition armed”, “Valve opened”, errors).
  - Admin panel UI for viewing and filtering logs.

- **Backup and restore (database)**
  - UI card to create and download PostgreSQL backups.
  - UI to upload and restore from a `.sql` / `.dump` backup (when enabled and `pg_dump` / `pg_restore` are installed).

- **Theming and preferences**
  - Light/dark theme support.
  - Accent color preferences.
  - User preference fields stored in the database (e.g., temperature unit °C/°F, telemetry toggle).

---

## Architecture

High-level architecture:

- **Host / Server**
  - Raspberry Pi (or similar) running Linux.
  - Python + Flask app (this repo).
  - PostgreSQL (recommended) or other SQL database via SQLAlchemy.

- **Microcontroller**
  - ESP32 (or similar) connected via USB serial (`/dev/ttyACM0` or similar).
  - Sends telemetry messages to the Pi.
  - Receives control commands (e.g., arm/disarm/valve control).

- **Web stack**
  - Flask + Jinja2 templates.
  - SQLAlchemy ORM.
  - Flask-Login for authentication.
  - Flask-WTF for forms and CSRF.
  - Flask-Talisman (optional, in production) for HTTPS + security headers.
  - Frontend using HTML, TailwindCSS/Flowbite, and vanilla JavaScript.

- **Deployment**
  - Development: `flask run` or `python wsgi.py`.
  - Production: Gunicorn bound to `127.0.0.1:5000` behind Nginx with Let’s Encrypt TLS.

---
