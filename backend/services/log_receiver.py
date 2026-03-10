import socket
import threading
import logging
from services.log_parser import parse
from services.detector import analyze

logger = logging.getLogger(__name__)


class LogReceiver:
    """
    TCP server that listens for incoming rsyslog messages.
    Each connection is handled in a separate thread.
    On receiving a log line it: parses → analyzes → saves → emits via socketio.
    """

    def __init__(self, app, db, socketio, host="0.0.0.0", port=5140):
        self.app      = app
        self.db       = db
        self.socketio = socketio
        self.host     = host
        self.port     = port
        self._running = False

    def start(self):
        """Start the TCP listener in a background thread."""
        self._running = True
        thread = threading.Thread(target=self._listen, daemon=True)
        thread.start()
        logger.info(f"Log receiver listening on {self.host}:{self.port} (TCP)")

    def stop(self):
        self._running = False

    def _listen(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.host, self.port))
            server.listen(10)

            while self._running:
                try:
                    conn, addr = server.accept()
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(conn, addr),
                        daemon=True
                    )
                    client_thread.start()
                except Exception as e:
                    logger.error(f"Receiver error: {e}")

    def _handle_client(self, conn, addr):
        logger.info(f"New log source connected: {addr}")
        
        # Keep connection alive
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        
        buffer = ""
        with conn:
            conn.settimeout(300)  # 5 minute timeout instead of closing immediately
            while True:
                try:
                    data = conn.recv(4096).decode("utf-8", errors="ignore")
                    if not data:
                        break
                    buffer += data
                    while "\n" in buffer:
                        line, buffer = buffer.split("\n", 1)
                        self._process_line(line.strip())

                except socket.timeout:
                    continue  # timeout is fine, just keep waiting
                except Exception as e:
                    logger.error(f"Error handling client {addr}: {e}")
                    break

    def _process_line(self, raw: str):
        if not raw:
            return

        parsed = parse(raw)
        if not parsed:
            return

        with self.app.app_context():
            log_entry = self._save_log_entry(parsed)  # ← capture the returned entry
            suspicious = analyze(parsed)
            if suspicious:
                self._save_suspicious_event(suspicious, log_entry.id)  # ← pass the id
                self.socketio.emit("suspicious_event", suspicious_event_to_dict(suspicious))

        self.socketio.emit("log_entry", {
            "timestamp":   parsed["timestamp"].isoformat(),
            "host":        parsed["host"],
            "process":     parsed["process"],
            "log_type":    parsed["log_type"],
            "message":     parsed["message"],
        })

    def _save_log_entry(self, parsed: dict):
        from models.log_entry import LogEntry
        entry = LogEntry(
            timestamp   = parsed["timestamp"],
            host        = parsed["host"],
            process     = parsed["process"],
            pid         = parsed["pid"],
            message     = parsed["message"],
            log_type    = parsed["log_type"],
            raw         = parsed["raw"],
        )
        self.db.session.add(entry)
        self.db.session.commit()
        return entry
        
    def _save_suspicious_event(self, event: dict, log_id: int):
        from models.log_entry import SuspiciousEvent
        se = SuspiciousEvent(
            timestamp   = event["timestamp"],
            event_type  = event["event_type"],
            severity    = event["severity"],
            source_ip   = event.get("source_ip"),
            target_host = event.get("target_host"), 
            username    = event.get("username"),
            description = event["description"],
            raw_log_id  = log_id,
            status      = "open",
        )
        self.db.session.add(se)
        self.db.session.commit()


def suspicious_event_to_dict(event: dict) -> dict:
    return {
        "event_type":  event["event_type"],
        "severity":    event["severity"],
        "source_ip":   event.get("source_ip"),
        "target_host": event.get("target_host"),
        "username":    event.get("username"),
        "description": event["description"],
        "timestamp":   event["timestamp"].isoformat(),
    }
