from flask import Blueprint, jsonify, request
from models.log_entry import LogEntry, SuspiciousEvent
from database.db import db

api = Blueprint("api", __name__, url_prefix="/api")


# ── Log Entries ────────────────────────────────────────────────────────────────

@api.route("/logs", methods=["GET"])
def get_logs():
    """Return recent log entries. Optional filters: log_type, host, limit."""
    log_type = request.args.get("log_type")
    host     = request.args.get("host")
    limit    = int(request.args.get("limit", 100))

    query = LogEntry.query.order_by(LogEntry.timestamp.desc())
    if log_type:
        query = query.filter_by(log_type=log_type)
    if host:
        query = query.filter_by(host=host)

    return jsonify([l.to_dict() for l in query.limit(limit).all()])


# ── Suspicious Events ──────────────────────────────────────────────────────────

@api.route("/events", methods=["GET"])
def get_suspicious_events():
    """Return suspicious events. Optional filters: severity, event_type, status, target_host, limit."""
    severity    = request.args.get("severity")
    event_type  = request.args.get("event_type")
    status      = request.args.get("status")
    target_host = request.args.get("target_host")
    limit       = int(request.args.get("limit", 50))

    query = SuspiciousEvent.query.order_by(SuspiciousEvent.timestamp.desc())
    if severity:
        query = query.filter_by(severity=severity)
    if event_type:
        query = query.filter_by(event_type=event_type)
    if status:
        query = query.filter_by(status=status)
    if target_host:
        query = query.filter_by(target_host=target_host)

    return jsonify([e.to_dict() for e in query.limit(limit).all()])


@api.route("/events/open", methods=["GET"])
def get_open_events():
    """Return only open and investigating alerts."""
    target_host = request.args.get("target_host")

    query = SuspiciousEvent.query.filter(
        SuspiciousEvent.status != "resolved"
    ).order_by(SuspiciousEvent.timestamp.desc())

    if target_host:
        query = query.filter_by(target_host=target_host)

    return jsonify([e.to_dict() for e in query.all()])


@api.route("/events/<int:event_id>/status", methods=["PATCH"])
def update_event_status(event_id):
    event  = db.session.get(SuspiciousEvent, event_id)
    if not event:
        return jsonify({"error": "Event not found"}), 404

    data   = request.get_json()
    status = data.get("status")

    if status not in ["open", "investigating", "resolved"]:
        return jsonify({"error": "Invalid status"}), 400

    event.status = status
    db.session.commit()
    return jsonify(event.to_dict())


# ── Stats ──────────────────────────────────────────────────────────────────────

@api.route("/stats", methods=["GET"])
def get_stats():
    """Return summary stats for the dashboard."""
    target_host = request.args.get("target_host")

    log_query   = LogEntry.query
    event_query = SuspiciousEvent.query

    if target_host:
        log_query   = log_query.filter_by(host=target_host)
        event_query = event_query.filter_by(target_host=target_host)

    total_logs   = log_query.count()
    total_events = event_query.count()
    open_alerts  = event_query.filter_by(status="open").count()

    return jsonify({
        "total_logs":   total_logs,
        "total_events": total_events,
        "open_alerts":  open_alerts,
        "by_severity": {
            "critical": event_query.filter_by(severity="critical").count(),
            "high":     event_query.filter_by(severity="high").count(),
            "medium":   event_query.filter_by(severity="medium").count(),
            "low":      event_query.filter_by(severity="low").count(),
        },
        "by_type": {
            "brute_force":           event_query.filter_by(event_type="brute_force").count(),
            "brute_force_success":   event_query.filter_by(event_type="brute_force_success").count(),
            "privilege_escalation":  event_query.filter_by(event_type="privilege_escalation").count(),
            "root_login_attempt":    event_query.filter_by(event_type="root_login_attempt").count(),
            "unauthorized_sudo":     event_query.filter_by(event_type="unauthorized_sudo").count(),
            "sensitive_file_access": event_query.filter_by(event_type="sensitive_file_access").count(),
        }
    })


# ── Hosts ──────────────────────────────────────────────────────────────────────

@api.route("/hosts", methods=["GET"])
def get_hosts():
    """Return list of all unique hosts sending logs."""
    hosts = db.session.query(LogEntry.host).distinct().all()
    return jsonify([h[0] for h in hosts if h[0]])