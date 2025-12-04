#!/usr/bin/env python3
import psycopg2, random, time, os
from datetime import datetime
from rich.console import Console
from rich.table import Table

DB_NAME = os.getenv("DB_NAME", "jet_dashboard")
DB_USER = os.getenv("DB_USER", "flask")
DB_PASSWORD = os.getenv("DB_PASS")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")

if DB_PASSWORD is None:
    raise RuntimeError("DB_PASS is not set; please configure the database password in the environment.")

console = Console()

def connect_db():
    return psycopg2.connect(
        dbname=DB_NAME, user=DB_USER,
        password=DB_PASSWORD, host=DB_HOST, port=DB_PORT
    )

def read_sensors():
    return {
        "timestamp": datetime.now(),
        "intake_temp_c": round(random.uniform(15, 40), 2),
        "exhaust_temp_c": round(random.uniform(400, 850), 2),
        "rpm": random.randint(5000, 15000),
        "thrust_n": round(random.uniform(20000, 120000), 2),
        "fuel_flow_kg_s": round(random.uniform(0.2, 1.5), 3),
        "status": random.choice(["Nominal", "High Temp", "Low Thrust", "Fuel Surge"])
    }

def insert_log(conn, data):
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO engine_log (timestamp, intake_temp_c, exhaust_temp_c, rpm, thrust_n, fuel_flow_kg_s, status)
            VALUES (%s, %s, %s, %s, %s, %s, %s);
        """, tuple(data.values()))
    conn.commit()

def display_table(data):
    table = Table(title="🚀 Propulsion Jet Engine Telemetry")
    for c in ["Time","Intake (°C)","Exhaust (°C)","RPM","Thrust (N)","Fuel Flow (kg/s)","Status"]:
        table.add_column(c)
    table.add_row(
        data["timestamp"].strftime("%H:%M:%S"),
        str(data["intake_temp_c"]), str(data["exhaust_temp_c"]),
        str(data["rpm"]), str(data["thrust_n"]),
        str(data["fuel_flow_kg_s"]), data["status"]
    )
    console.clear(); console.print(table)

def main():
    console.print("[bold cyan]Starting Jet Engine Logger...[/bold cyan]")
    conn = connect_db()
    try:
        while True:
            data = read_sensors()
            insert_log(conn, data)
            display_table(data)
            time.sleep(2)
    except KeyboardInterrupt:
        console.print("[red]Stopped by user.[/red]")
    finally:
        conn.close()

if __name__ == "__main__":
    main()
