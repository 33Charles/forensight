from database.db import db
from datetime import datetime

class LogEntry(db.Model):
    __tablename__ = "log_entries"

    id            = db.Column(db.Integer, primary_key=True)
    timestamp     = db.Column(db.DateTime, default=datetime.utcnow)
    source_host   = db.Column(db.String(100))
    process       = db.Column(db.String(100))
    pid           = db.Column(db.Integer, nullable=True)
    message       = db.Column(db.Text)
    log_type      = db.Column(db.String(50))
    raw           = db.Column(db.Text)

    def to_dict(self):
        return {
            "id":          self.id,
            "timestamp":   self.timestamp.isoformat(),
            "source_host": self.source_host,
            "process":     self.process,
            "pid":         self.pid,
            "message":     self.message,
            "log_type":    self.log_type,
            "raw":         self.raw,
        }


class SuspiciousEvent(db.Model):
    __tablename__ = "suspicious_events"

    id            = db.Column(db.Integer, primary_key=True)
    timestamp     = db.Column(db.DateTime, default=datetime.utcnow)
    event_type    = db.Column(db.String(100))
    severity      = db.Column(db.String(20))
    source_ip     = db.Column(db.String(50), nullable=True)
    username      = db.Column(db.String(100), nullable=True)
    description   = db.Column(db.Text)
    raw_log_id    = db.Column(db.Integer, db.ForeignKey("log_entries.id"), nullable=True)
    status        = db.Column(db.String(20), default="open")  # open, investigating, resolved

    def to_dict(self):
        return {
            "id":          self.id,
            "timestamp":   self.timestamp.isoformat(),
            "event_type":  self.event_type,
            "severity":    self.severity,
            "source_ip":   self.source_ip,
            "username":    self.username,
            "description": self.description,
            "raw_log_id":  self.raw_log_id,
            "status":      self.status,
        }