# app/models/login_log.py

from datetime import datetime
from app import db


class LoginLog(db.Model):
    __tablename__ = "login_logs"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=True)
    ip = db.Column(db.String(64), nullable=True)
    status = db.Column(db.String(40), nullable=False)
    user_agent = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def __repr__(self):
        return f"<LoginLog {self.username} {self.status} {self.timestamp}>"
