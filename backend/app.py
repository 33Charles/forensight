import logging
import colorlog

handler = colorlog.StreamHandler()
handler.setFormatter(colorlog.ColoredFormatter(
    "%(log_color)s%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    log_colors={
        "DEBUG":    "cyan",
        "INFO":     "green",
        "WARNING":  "yellow",
        "ERROR":    "red",
        "CRITICAL": "bold_red",
    }
))

logging.root.setLevel(logging.INFO)
logging.root.addHandler(handler)

from flask import Flask, jsonify
from flask_socketio import SocketIO
from flask_cors import CORS
from flask_jwt_extended import JWTManager

from config import Config
from database.db import db, init_db
from api.routes import api
from api.auth_routes import auth_bp
from api.user_routes import users_bp
from services.log_receiver import LogReceiver
import traceback
import threading
import getpass
import sys

logger = logging.getLogger(__name__)

socketio = SocketIO(cors_allowed_origins="*", async_mode='threading')

original_excepthook = threading.excepthook
def custom_excepthook(args):
    print("Thread exception:")
    traceback.print_exception(args.exc_type, args.exc_value, args.exc_traceback)
threading.excepthook = custom_excepthook


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    CORS(app)
    socketio.init_app(app)
    init_db(app)

    # ── JWT setup ──────────────────────────────────────────────────────────
    jwt = JWTManager(app)

    @jwt.unauthorized_loader
    def unauthorized_response(err):
        return jsonify({"error": "Authentication required", "detail": err}), 401

    @jwt.invalid_token_loader
    def invalid_token_response(err):
        return jsonify({"error": "Invalid token", "detail": err}), 401

    @jwt.expired_token_loader
    def expired_token_response(jwt_header, jwt_data):
        return jsonify({"error": "Token has expired"}), 401

    # ── Blueprints ─────────────────────────────────────────────────────────
    app.register_blueprint(api)
    app.register_blueprint(auth_bp)
    app.register_blueprint(users_bp)

    return app


def _first_run_setup(app):
    """
    Check if any users exist. If not, prompt to create the first admin account.
    Called once before starting the server.
    """
    from models.user import User

    with app.app_context():
        user_count = User.query.count()
        if user_count > 0:
            return  # Users already exist, skip setup

    print("")
    print("=" * 55)
    print("  Forensight — First Run Setup")
    print("  No users found. Create the super admin account.")
    print("=" * 55)

    while True:
        username = input("\n  Admin username: ").strip()
        if not username:
            print("  Username cannot be empty.")
            continue
        if len(username) < 3:
            print("  Username must be at least 3 characters.")
            continue
        break

    while True:
        password = getpass.getpass("  Admin password: ")
        if len(password) < 8:
            print("  Password must be at least 8 characters.")
            continue
        confirm = getpass.getpass("  Confirm password: ")
        if password != confirm:
            print("  Passwords do not match.")
            continue
        break

    with app.app_context():
        from models.user import User
        admin = User(
            username   = username,
            role       = "admin",
            created_by = "system",
        )
        admin.set_password(password)
        db.session.add(admin)
        db.session.commit()

    print(f"\n  ✓ Admin account '{username}' created successfully!")
    print("=" * 55)
    print("")


if __name__ == "__main__":
    app = create_app()

    # First run setup — prompts for admin credentials if no users exist
    _first_run_setup(app)

    receiver = LogReceiver(
        app=app, db=db, socketio=socketio,
        host=Config.LOG_RECEIVER_HOST,
        port=Config.LOG_RECEIVER_PORT,
    )
    receiver.start()

    socketio.run(app, host="0.0.0.0", port=5000, debug=False, use_reloader=False, allow_unsafe_werkzeug=True)