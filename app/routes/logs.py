from flask import Blueprint, render_template, jsonify, send_file
# Created by Anthony Kaiser
import csv, io, json
from datetime import datetime
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from app import db

bp_logs = Blueprint("logs", __name__)

@bp_logs.route("/logs")
def logs_page():
    return render_template("logs.html")


def _fetch_engine_logs(limit=None):
    """Return rows from engine_log ordered by newest first."""
    sql = """
        SELECT timestamp, intake_temp_c, exhaust_temp_c, rpm, thrust_n, fuel_flow_kg_s, status
        FROM engine_log
        ORDER BY timestamp DESC
    """
    try:
        if limit:
            sql += " LIMIT :limit"
            result = db.session.execute(text(sql), {"limit": limit})
        else:
            result = db.session.execute(text(sql))
        return result.fetchall(), None, False
    except SQLAlchemyError as exc:
        # Likely table missing or DB unreachable; fail gracefully.
        db.session.rollback()
        msg = str(exc)
        missing_table = "UndefinedTable" in msg or "relation \"engine_log\" does not exist" in msg
        return [], (None if missing_table else msg), missing_table


@bp_logs.route("/api/logs")
def api_logs():
    try:
        rows, err, missing = _fetch_engine_logs(limit=100)
        if missing:
            sample = [{
                "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                "intake_temp_c": 32.5,
                "exhaust_temp_c": 285.0,
                "rpm": 42000,
                "thrust_n": 12.4,
                "fuel_flow_kg_s": 0.14,
                "status": "sample"
            }]
            return jsonify({"logs": sample, "warning": "engine_log table does not exist yet. Showing sample data."}), 200
        if err:
            return jsonify({"error": err, "logs": []}), 500
        logs = [
            {
                "timestamp": r[0].strftime("%Y-%m-%d %H:%M:%S") if r[0] else "",
                "intake_temp_c": r[1],
                "exhaust_temp_c": r[2],
                "rpm": r[3],
                "thrust_n": r[4],
                "fuel_flow_kg_s": r[5],
                "status": r[6],
            }
            for r in rows
        ]
        return jsonify(logs)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
        

@bp_logs.route("/download/logs/<fmt>")
def download_logs(fmt):
    try:
        rows, err, missing = _fetch_engine_logs()
        if missing:
            # Provide a sample download so UI isn't blocked
            rows = [(
                datetime.utcnow(),
                32.5, 285.0, 42000, 12.4, 0.14, "sample"
            )]
            err = None
        if err:
            return jsonify({"error": err}), 500

        if fmt == "csv":
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow([
                "timestamp", "intake_temp_c", "exhaust_temp_c",
                "rpm", "thrust_n", "fuel_flow_kg_s", "status"
            ])
            for r in rows:
                writer.writerow([
                    r[0].strftime("%Y-%m-%d %H:%M:%S") if r[0] else "",
                    r[1], r[2], r[3], r[4], r[5], r[6]
                ])
            output.seek(0)
            return send_file(
                io.BytesIO(output.getvalue().encode("utf-8")),
                mimetype="text/csv",
                as_attachment=True,
                download_name=f"engine_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            )
        elif fmt == "json":
            logs = [
                {
                    "timestamp": r[0].strftime("%Y-%m-%d %H:%M:%S") if r[0] else "",
                    "intake_temp_c": r[1],
                    "exhaust_temp_c": r[2],
                    "rpm": r[3],
                    "thrust_n": r[4],
                    "fuel_flow_kg_s": r[5],
                    "status": r[6],
                }
                for r in rows
            ]
            output = io.StringIO(json.dumps(logs, indent=2))
            return send_file(
                io.BytesIO(output.getvalue().encode("utf-8")),
                mimetype="application/json",
                as_attachment=True,
                download_name=f"engine_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            )
        else:
            return jsonify({"error": "Invalid format"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500
