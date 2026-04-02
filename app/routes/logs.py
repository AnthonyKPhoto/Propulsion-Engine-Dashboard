from flask import Blueprint, render_template, jsonify, send_file, abort
from flask_login import login_required, current_user
import csv, io, json
from datetime import datetime
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from app import db

bp_logs = Blueprint("logs", __name__)

@bp_logs.route("/logs")
@login_required
def logs_page():
    return render_template("logs.html")


def _fetch_engine_logs(limit=None):
    """Return rows from engine_log ordered by newest first."""
    sql = """
        SELECT timestamp, intake_temp_c, exhaust_temp_c, rpm, fuel_pressure, status
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
        db.session.rollback()
        msg = str(exc)
        missing_table = "UndefinedTable" in msg or "relation \"engine_log\" does not exist" in msg
        return [], (None if missing_table else msg), missing_table


@bp_logs.route("/api/logs")
@login_required
def api_logs():
    try:
        rows, err, missing = _fetch_engine_logs(limit=200)
        if missing:
            return jsonify({"logs": [], "warning": "engine_log table does not exist yet. Start logging to create it."}), 200
        if err:
            return jsonify({"error": err, "logs": []}), 500
        logs = [
            {
                "timestamp": r[0].strftime("%Y-%m-%d %H:%M:%S") if r[0] else "",
                "intake_temp_c": r[1],
                "exhaust_temp_c": r[2],
                "rpm": r[3],
                "fuel_pressure": r[4],
                "status": r[5],
            }
            for r in rows
        ]
        return jsonify(logs)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@bp_logs.route("/api/logs/reset", methods=["POST"])
@login_required
def reset_logs():
    role = getattr(current_user, "role_key", "viewer")
    if role != "admin":
        return jsonify({"ok": False, "message": "Admin role required."}), 403
    try:
        db.session.execute(text("DELETE FROM engine_log"))
        db.session.commit()
        return jsonify({"ok": True, "message": "All log data cleared."})
    except SQLAlchemyError as exc:
        db.session.rollback()
        return jsonify({"ok": False, "message": str(exc)}), 500


@bp_logs.route("/download/logs/<fmt>")
def download_logs(fmt):
    try:
        rows, err, missing = _fetch_engine_logs()
        if missing:
            return jsonify({"error": "No log data yet."}), 404
        if err:
            return jsonify({"error": err}), 500

        if fmt == "csv":
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["timestamp", "intake_temp_c", "exhaust_temp_c", "rpm", "fuel_pressure", "status"])
            for r in rows:
                writer.writerow([
                    r[0].strftime("%Y-%m-%d %H:%M:%S") if r[0] else "",
                    r[1], r[2], r[3], r[4], r[5]
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
                    "fuel_pressure": r[4],
                    "status": r[5],
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
