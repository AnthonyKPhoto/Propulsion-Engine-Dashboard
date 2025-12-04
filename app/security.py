# /opt/jet_dashboard/app/security.py
from functools import wraps
from flask import abort
from flask_login import current_user

def user_has_role(*roles):
    if not current_user.is_authenticated:
        return False
    user_roles = set((current_user.roles or "").split(",")) if isinstance(current_user.roles, str) else set(current_user.roles or [])
    return any(r in user_roles for r in roles)

def role_required(*required_roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated or not user_has_role(*required_roles):
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return decorator
