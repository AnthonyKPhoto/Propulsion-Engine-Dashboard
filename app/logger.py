#!/usr/bin/env python3
"""
Real-time engine data logger.

Connects to the running Jet Dashboard server via SocketIO, receives live
sensor and control-state events, and writes them into the engine_log table.
"""

import os
import threading
import time
from datetime import datetime

import psycopg2
import socketio
from rich.console import Console
from rich.table import Table

# ── Config ────────────────────────────────────────────────────────────────────
DB_NAME       = os.getenv("DB_NAME", "jet_dashboard")
DB_USER       = os.getenv("DB_USER", "flask")
DB_PASSWORD   = os.getenv("DB_PASS")
DB_HOST       = os.getenv("DB_HOST", "localhost")
DB_PORT       = os.getenv("DB_PORT", "5432")
LOGGER_SECRET = os.getenv("LOGGER_SECRET")
DASHBOARD_URL = os.getenv("DASHBOARD_URL", "http://localhost:8080")
LOG_INTERVAL  = float(os.getenv("LOG_INTERVAL", "2"))

if not DB_PASSWORD:
    raise RuntimeError("DB_PASS is not set.")
if not LOGGER_SECRET:
    raise RuntimeError("LOGGER_SECRET is not set.")

# ── Shared live state ─────────────────────────────────────────────────────────
_lock = threading.Lock()
_live = {
    "intake_temp_c":  None,
    "exhaust_temp_c": None,
    "rpm":            None,
    "fuel_pressure":  None,
    "system_state":   "IDLE",
}

console = Console()

# ── SocketIO client ───────────────────────────────────────────────────────────
sio = socketio.Client(logger=False, engineio_logger=False)


@sio.event
def connect():
    console.print("[bold green]Connected to dashboard.[/bold green]")


@sio.event
def disconnect():
    console.print("[bold red]Disconnected from dashboard.[/bold red]")


@sio.on("sensor_update")
def on_sensor_update(data):
    with _lock:
        val = data.get("intake_temp") or data.get("intake") or data.get("intake_temp_c")
        if val is not None:
            _live["intake_temp_c"] = float(val)

        val = data.get("exhaust_temp") or data.get("exhaust") or data.get("exhaust_temp_c")
        if val is not None:
            _live["exhaust_temp_c"] = float(val)

        val = data.get("rpm")
        if val is not None:
            _live["rpm"] = float(val)

        val = data.get("fuel_pressure") or data.get("pressure")
        if val is not None:
            _live["fuel_pressure"] = float(val)


@sio.on("control_state_update")
def on_control_state(data):
    with _lock:
        _live["system_state"] = data.get("system_state", "IDLE")


# ── Database helpers ──────────────────────────────────────────────────────────
def connect_db():
    return psycopg2.connect(
        dbname=DB_NAME, user=DB_USER,
        password=DB_PASSWORD, host=DB_HOST, port=DB_PORT
    )


def ensure_table(conn):
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS engine_log (
                id             SERIAL PRIMARY KEY,
                timestamp      TIMESTAMPTZ DEFAULT NOW(),
                intake_temp_c  DOUBLE PRECISION,
                exhaust_temp_c DOUBLE PRECISION,
                rpm            DOUBLE PRECISION,
                fuel_pressure  DOUBLE PRECISION,
                status         VARCHAR(64)
            );
        """)
        cur.execute("""
            ALTER TABLE engine_log
                ADD COLUMN IF NOT EXISTS fuel_pressure DOUBLE PRECISION;
        """)
    conn.commit()


def insert_log(conn, snapshot):
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO engine_log
                (timestamp, intake_temp_c, exhaust_temp_c, rpm, fuel_pressure, status)
            VALUES (%s, %s, %s, %s, %s, %s);
        """, (
            datetime.utcnow(),
            snapshot["intake_temp_c"],
            snapshot["exhaust_temp_c"],
            snapshot["rpm"],
            snapshot["fuel_pressure"],
            snapshot["system_state"],
        ))
    conn.commit()


# ── Display ───────────────────────────────────────────────────────────────────
def _fmt(val):
    return f"{val:.2f}" if val is not None else "—"


def display_table(snapshot):
    table = Table(title="Hybrid Turbojet Engine Telemetry  [Live]")
    for col in ["Time", "Intake (°C)", "Exhaust (°C)", "RPM", "Fuel Pressure (PSI)", "State"]:
        table.add_column(col, justify="right")
    table.add_row(
        datetime.utcnow().strftime("%H:%M:%S"),
        _fmt(snapshot["intake_temp_c"]),
        _fmt(snapshot["exhaust_temp_c"]),
        _fmt(snapshot["rpm"]),
        _fmt(snapshot["fuel_pressure"]),
        snapshot["system_state"],
    )
    console.clear()
    console.print(table)


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    console.print("[bold cyan]Starting Jet Engine Logger (Live)...[/bold cyan]")

    try:
        sio.connect(
            DASHBOARD_URL,
            auth={"token": LOGGER_SECRET},
            transports=["websocket"],
        )
    except Exception as exc:
        console.print(f"[bold red]Could not connect to dashboard: {exc}[/bold red]")
        return

    conn = connect_db()
    ensure_table(conn)

    try:
        while True:
            time.sleep(LOG_INTERVAL)

            with _lock:
                snapshot = dict(_live)

            has_data = any(
                snapshot[k] is not None
                for k in ("intake_temp_c", "exhaust_temp_c", "rpm")
            )

            if has_data:
                try:
                    insert_log(conn, snapshot)
                except psycopg2.Error as exc:
                    console.print(f"[red]DB error: {exc}[/red]")
                    try:
                        conn = connect_db()
                    except Exception:
                        pass

            display_table(snapshot)

    except KeyboardInterrupt:
        console.print("[red]Stopped by user.[/red]")
    finally:
        sio.disconnect()
        conn.close()


if __name__ == "__main__":
    main()
