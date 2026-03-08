from flask import Blueprint, jsonify, request
from models.log_entry import LogEntry, SuspiciousEvent
from database.db import db

api = Blueprint("api", __name__, url_prefix="/api")


# ── Log Entries ────────────────────────────────────────────────────────────

@api.route("/logs", methods=["GET"])
def get_logs():
    """Return recent log entries. Optional filters: log_type, limit."""
    log_type = request.args.get("log_type")
    limit    = int(request.args.get("limit", 100))

    query = LogEntry.query.order_by(LogEntry.timestamp.desc())
    if log_type:
        query = query.filter_by(log_type=log_type)

    logs = query.limit(limit).all()
    return jsonify([l.to_dict() for l in logs])


# ── Suspicious Events ──────────────────────────────────────────────────────

@api.route("/events", methods=["GET"])
def get_suspicious_events():
    """Return suspicious events. Optional filters: severity, event_type, status, limit."""
    severity   = request.args.get("severity")
    event_type = request.args.get("event_type")
    status     = request.args.get("status")
    limit      = int(request.args.get("limit", 50))

    query = SuspiciousEvent.query.order_by(SuspiciousEvent.timestamp.desc())
    if severity:
        query = query.filter_by(severity=severity)
    if event_type:
        query = query.filter_by(event_type=event_type)
    if status:
        query = query.filter_by(status=status)

    events = query.limit(limit).all()
    return jsonify([e.to_dict() for e in events])


@api.route("/events/<int:event_id>/status", methods=["PATCH"])
def update_event_status(event_id):
    event  = SuspiciousEvent.query.get_or_404(event_id)
    data   = request.get_json()
    status = data.get("status")

    if status not in ["open", "investigating", "resolved"]:
        return jsonify({"error": "Invalid status"}), 400

    event.status = status
    db.session.commit()
    return jsonify(event.to_dict())


@api.route("/events/open", methods=["GET"])
def get_open_events():
    events = SuspiciousEvent.query.filter(
        SuspiciousEvent.status != "resolved"
    ).order_by(SuspiciousEvent.timestamp.desc()).all()
    return jsonify([e.to_dict() for e in events])

# ── Stats for dashboard ────────────────────────────────────────────────────

@api.route("/stats", methods=["GET"])
def get_stats():
    """Return summary stats for the dashboard."""
    total_logs    = LogEntry.query.count()
    total_events  = SuspiciousEvent.query.count()
    critical      = SuspiciousEvent.query.filter_by(severity="critical").count()
    high          = SuspiciousEvent.query.filter_by(severity="high").count()
    medium        = SuspiciousEvent.query.filter_by(severity="medium").count()

    # Count by event type
    brute_force   = SuspiciousEvent.query.filter_by(event_type="brute_force").count()
    priv_esc      = SuspiciousEvent.query.filter_by(event_type="privilege_escalation").count()
    file_access   = SuspiciousEvent.query.filter_by(event_type="sensitive_file_access").count()

    return jsonify({
        "total_logs":   total_logs,
        "total_events": total_events,
        "by_severity": {
            "critical": critical,
            "high":     high,
            "medium":   medium,
        },
        "by_type": {
            "brute_force":           brute_force,
            "privilege_escalation":  priv_esc,
            "sensitive_file_access": file_access,
        }
    })
