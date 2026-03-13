from functools import wraps
from flask import jsonify
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
from models.user import User

# ── Role hierarchy ─────────────────────────────────────────────────────────────
ROLE_PERMISSIONS = {
    "admin":   ["view", "update_status", "manage_users", "reload_rules", "ingest"],
    "analyst": ["view", "update_status", "ingest"],
    "viewer":  ["view"],
}

def _has_permission(role: str, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, [])


def jwt_required_with_role(permission: str):
    """
    Decorator that requires a valid JWT and checks the user has
    the required permission based on their role.
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            verify_jwt_in_request()
            username = get_jwt_identity()
            user     = User.query.filter_by(username=username, is_active=True).first()

            if not user:
                return jsonify({"error": "User not found or inactive"}), 401

            if not _has_permission(user.role, permission):
                return jsonify({
                    "error": f"Permission denied — requires '{permission}' permission",
                    "your_role": user.role,
                }), 403

            return fn(*args, **kwargs)
        return wrapper
    return decorator


def get_current_user() -> User | None:
    """Get the current authenticated user from JWT identity."""
    try:
        verify_jwt_in_request()
        username = get_jwt_identity()
        return User.query.filter_by(username=username, is_active=True).first()
    except Exception:
        return None