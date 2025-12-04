# app/models/user.py
# Created by Anthony Kaiser

from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from app import db


class User(db.Model, UserMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)

    password_hash = db.Column(db.String(255), nullable=False)

    # Metadata
    role = db.Column(db.String(20), default="user")         # "admin" / "user"
    email = db.Column(db.String(255), nullable=True, index=True)

    # Appearance / prefs
    theme = db.Column(db.String(20), default="dark")
    accent = db.Column(db.String(20), default="sky")
    profile_image = db.Column(db.String(255), default="default.png")

    # Dashboard-related prefs
    telemetry_enabled = db.Column(db.Boolean, default=True)
    temp_unit = db.Column(db.String(5), default="C")        # "C" or "F"
    totp_secret = db.Column(db.String(64), nullable=True)
    is_2fa_enabled = db.Column(db.Boolean, default=False)

    # Lifecycle
    is_temp_password = db.Column(db.Boolean, default=False)
    is_approved = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Flask-Login identifier -> use DB primary key
    def get_id(self):
        return str(self.id)

    # Password helpers
    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    # Role helpers
    def is_admin(self):
        return (self.role or "").lower() == "admin"

    def __repr__(self):
        return f"<User {self.username}>"
