# app/models/access_request.py

from datetime import datetime
from app import db


class AccessRequest(db.Model):
    __tablename__ = "access_requests"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    reason = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), default="pending", index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    approval_time = db.Column(db.DateTime, nullable=True)
    temp_password_shown = db.Column(db.Boolean, default=False)

    def is_pending(self):
        return (self.status or "").lower() == "pending"
