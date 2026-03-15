from database.db import db
from datetime import datetime

class LogEntry(db.Model):
    __tablename__ = "log_entries"

    id          = db.Column(db.Integer, primary_key=True)
    timestamp   = db.Column(db.DateTime, default=datetime.utcnow)
    host        = db.Column(db.String(100))
    process     = db.Column(db.String(100))
    pid         = db.Column(db.Integer, nullable=True)
    message     = db.Column(db.Text)
    log_type    = db.Column(db.String(50))
    raw         = db.Column(db.Text)
    source      = db.Column(db.String(20), default="live")

    def to_dict(self):
        return {
            "id":        self.id,
            "timestamp": self.timestamp.isoformat(),
            "host":      self.host,
            "process":   self.process,
            "pid":       self.pid,
            "message":   self.message,
            "log_type":  self.log_type,
            "raw":       self.raw,
            "source":    self.source,
        }


class SuspiciousEvent(db.Model):
    __tablename__ = "suspicious_events"

    id               = db.Column(db.Integer, primary_key=True)
    timestamp        = db.Column(db.DateTime, default=datetime.utcnow)
    event_type       = db.Column(db.String(100))
    severity         = db.Column(db.String(20))
    source_ip        = db.Column(db.String(50),  nullable=True)
    target_host      = db.Column(db.String(100), nullable=True)
    username         = db.Column(db.String(100), nullable=True)
    description      = db.Column(db.Text)
    raw_log_id       = db.Column(db.Integer, db.ForeignKey("log_entries.id"), nullable=True)
    status           = db.Column(db.String(20),  default="open")
    resolved_at      = db.Column(db.DateTime,    nullable=True)
    source           = db.Column(db.String(20),  default="live")
    mitre_technique  = db.Column(db.String(50),  nullable=True)
    mitre_tactic     = db.Column(db.String(100), nullable=True)
    investigated_by  = db.Column(db.String(100), nullable=True)
    resolved_by      = db.Column(db.String(100), nullable=True)
    notes            = db.Column(db.Text,         nullable=True)
    assigned_to      = db.Column(db.String(100), nullable=True)  # set on reopen by admin
    reopened_at      = db.Column(db.DateTime,    nullable=True)  # when event was reopened

    def to_dict(self):
        return {
            "id":              self.id,
            "timestamp":       self.timestamp.isoformat(),
            "event_type":      self.event_type,
            "severity":        self.severity,
            "source_ip":       self.source_ip,
            "target_host":     self.target_host,
            "username":        self.username,
            "description":     self.description,
            "raw_log_id":      self.raw_log_id,
            "status":          self.status,
            "resolved_at":     self.resolved_at.isoformat() if self.resolved_at else None,
            "source":          self.source,
            "mitre_technique": self.mitre_technique,
            "mitre_tactic":    self.mitre_tactic,
            "investigated_by": self.investigated_by,
            "resolved_by":     self.resolved_by,
            "notes":           self.notes,
            "assigned_to":     self.assigned_to,
            "reopened_at":     self.reopened_at.isoformat() if self.reopened_at else None,
        }