import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    # Database
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{os.path.join(BASE_DIR, 'forensight.db')}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Log receiver settings
    LOG_RECEIVER_HOST = "0.0.0.0"   # Listen on all interfaces
    LOG_RECEIVER_PORT = 5140         # Using 5140 to avoid needing root privileges

    # Detection thresholds
    BRUTE_FORCE_THRESHOLD = 5        # Failed attempts before flagging
    BRUTE_FORCE_WINDOW = 60          # Time window in seconds

    # Flask
    SECRET_KEY = os.environ.get("SECRET_KEY", "darklight-dev-secret")
    DEBUG = True
