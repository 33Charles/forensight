from flask import Flask
from flask_socketio import SocketIO
from flask_cors import CORS

from config import Config
from database.db import db, init_db
from api.routes import api
from services.log_receiver import LogReceiver
import traceback
import threading


#socketio = SocketIO(cors_allowed_origins="*")
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
    app.register_blueprint(api)

    return app  # ← no receiver here anymore


if __name__ == "__main__":
    app = create_app()

    receiver = LogReceiver(
        app=app, db=db, socketio=socketio,
        host=Config.LOG_RECEIVER_HOST,
        port=Config.LOG_RECEIVER_PORT,
    )
    receiver.start()

    socketio.run(app, host="0.0.0.0", port=5000, debug=False, use_reloader=False)
