from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required
from models.user import User
from database.db import db
from services.auth import jwt_required_with_role, get_current_user

users_bp = Blueprint("users", __name__, url_prefix="/api/users")


@users_bp.route("", methods=["GET"])
@jwt_required_with_role("manage_users")
def get_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return jsonify([u.to_dict() for u in users])


@users_bp.route("", methods=["POST"])
@jwt_required_with_role("manage_users")
def create_user():
    data     = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "")
    role     = data.get("role", "viewer")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    if role not in ["admin", "analyst", "viewer"]:
        return jsonify({"error": "Invalid role. Must be admin, analyst, or viewer"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"error": f"Username '{username}' already exists"}), 409

    creator = get_current_user()
    user    = User(
        username   = username,
        role       = role,
        created_by = creator.username if creator else "system",
    )
    user.set_password(password)

    db.session.add(user)
    db.session.commit()

    return jsonify(user.to_dict()), 201


@users_bp.route("/<int:user_id>", methods=["PATCH"])
@jwt_required_with_role("manage_users")
def update_user(user_id):
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Prevent admin from disabling their own account
    current = get_current_user()
    if current and current.id == user_id and "is_active" in request.get_json():
        data = request.get_json()
        if data.get("is_active") is False:
            return jsonify({"error": "Cannot disable your own account"}), 400

    data = request.get_json()

    if "role" in data:
        if data["role"] not in ["admin", "analyst", "viewer"]:
            return jsonify({"error": "Invalid role"}), 400
        user.role = data["role"]

    if "is_active" in data:
        user.is_active = bool(data["is_active"])

    if "password" in data and data["password"]:
        user.set_password(data["password"])

    db.session.commit()
    return jsonify(user.to_dict())


@users_bp.route("/<int:user_id>", methods=["DELETE"])
@jwt_required_with_role("manage_users")
def delete_user(user_id):
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Prevent deleting your own account
    current = get_current_user()
    if current and current.id == user_id:
        return jsonify({"error": "Cannot delete your own account"}), 400

    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": f"User '{user.username}' deleted"})