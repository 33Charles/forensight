import socket
import threading
import logging
from services.log_parser import parse
from services.detector import analyze

logger = logging.getLogger(__name__)

# SQLite cannot handle concurrent writes — serialize all DB operations
_db_lock = threading.Lock()


class LogReceiver:
    def __init__(self, app, db, socketio, host="0.0.0.0", port=5140):
        self.app      = app
        self.db       = db
        self.socketio = socketio
        self.host     = host
        self.port     = port
        self._running = False

    def start(self):
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
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

        buffer = ""
        with conn:
            conn.settimeout(300)
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
                    continue
                except Exception as e:
                    logger.error(f"Error handling client {addr}: {e}")
                    break

    def _process_line(self, raw: str, source: str = "live"):
        if not raw:
            return

        parsed = parse(raw)
        if not parsed:
            return

        # Run detection outside the lock — pure in-memory, no DB needed
        suspicious = analyze(parsed)

        # Serialize all DB writes to prevent SQLite locking
        with _db_lock:
            try:
                with self.app.app_context():
                    log_entry = self._save_log_entry(parsed, source)
                    if suspicious:
                        se = self._save_suspicious_event(suspicious, log_entry.id, source)
                        # Emit the full DB object so frontend gets id, status, source
                        self.socketio.emit("suspicious_event", se.to_dict())
            except Exception as e:
                logger.error(f"DB write error: {e}")
                return

        self.socketio.emit("log_entry", {
            "timestamp": parsed["timestamp"].isoformat(),
            "host":      parsed["host"],
            "process":   parsed["process"],
            "log_type":  parsed["log_type"],
            "message":   parsed["message"],
            "source":    source,
        })

    def _save_log_entry(self, parsed: dict, source: str = "live"):
        from models.log_entry import LogEntry
        entry = LogEntry(
            timestamp = parsed["timestamp"],
            host      = parsed["host"],
            process   = parsed["process"],
            pid       = parsed["pid"],
            message   = parsed["message"],
            log_type  = parsed["log_type"],
            raw       = parsed["raw"],
            source    = source,
        )
        self.db.session.add(entry)
        self.db.session.commit()
        return entry

    def _save_suspicious_event(self, event: dict, log_id: int, source: str = "live"):
        from models.log_entry import SuspiciousEvent, EventAuditLog
        se = SuspiciousEvent(
            timestamp       = event["timestamp"],
            event_type      = event["event_type"],
            severity        = event["severity"],
            source_ip       = event.get("source_ip"),
            target_host     = event.get("target_host"),
            username        = event.get("username"),
            description     = event["description"],
            raw_log_id      = log_id,
            status          = "open",
            source          = source,
            mitre_technique = event.get("mitre_technique"),
            mitre_tactic    = event.get("mitre_tactic"),
        )
        self.db.session.add(se)
        self.db.session.flush()  # get se.id before commit

        # Audit log — use event timestamp not utcnow() so it matches the
        # actual detection time, not when the DB write happened
        audit = EventAuditLog(
            event_id     = se.id,
            timestamp    = se.timestamp,
            action       = "created",
            performed_by = "system",
            details      = f"Auto-detected: {event['event_type']} ({event['severity']})",
        )
        self.db.session.add(audit)
        self.db.session.commit()
        return se


def _suspicious_to_dict(event: dict) -> dict:
    return {
        "event_type":      event["event_type"],
        "severity":        event["severity"],
        "source_ip":       event.get("source_ip"),
        "target_host":     event.get("target_host"),
        "username":        event.get("username"),
        "description":     event["description"],
        "timestamp":       event["timestamp"].isoformat(),
        "mitre_technique": event.get("mitre_technique"),
        "mitre_tactic":    event.get("mitre_tactic"),
    }