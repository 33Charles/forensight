import os
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    # Database — timeout prevents "database is locked" under concurrent writes
    SQLALCHEMY_DATABASE_URI = (
        f"sqlite:///{os.path.join(BASE_DIR, 'forensight.db')}"
        f"?timeout=30&check_same_thread=False"
    )
    SQLALCHEMY_ENGINE_OPTIONS = {
        "connect_args": {
            "timeout":           30,
            "check_same_thread": False,
        }
    }
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Log receiver settings
    LOG_RECEIVER_HOST = "0.0.0.0"
    LOG_RECEIVER_PORT = 5140

    # Detection thresholds (legacy — now managed via detection_rules.yaml)
    BRUTE_FORCE_THRESHOLD = 5
    BRUTE_FORCE_WINDOW    = 60

    # Flask
    SECRET_KEY = os.environ.get("SECRET_KEY", "darklight-dev-secret-change-in-prod")
    DEBUG      = False

    # JWT — reuses Flask secret key so only one env var needed in production
    JWT_SECRET_KEY            = os.environ.get("JWT_SECRET_KEY", SECRET_KEY)
    JWT_ACCESS_TOKEN_EXPIRES  = timedelta(hours=8)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)