from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from models.log_entry import LogEntry, SuspiciousEvent
from database.db import db
from datetime import datetime, timedelta
from sqlalchemy import func
from services.auth import jwt_required_with_role

api = Blueprint("api", __name__, url_prefix="/api")


# ── Log Entries ────────────────────────────────────────────────────────────────

@api.route("/logs", methods=["GET"])
@jwt_required_with_role("view")
def get_logs():
    log_type = request.args.get("log_type")
    host     = request.args.get("host")
    source   = request.args.get("source")
    limit    = int(request.args.get("limit", 100))

    query = LogEntry.query.order_by(LogEntry.timestamp.desc())
    if log_type: query = query.filter_by(log_type=log_type)
    if host:     query = query.filter_by(host=host)
    if source:   query = query.filter_by(source=source)

    return jsonify([l.to_dict() for l in query.limit(limit).all()])


# ── Suspicious Events ──────────────────────────────────────────────────────────

@api.route("/events", methods=["GET"])
@jwt_required_with_role("view")
def get_suspicious_events():
    severity    = request.args.get("severity")
    event_type  = request.args.get("event_type")
    status      = request.args.get("status")
    target_host = request.args.get("target_host")
    source      = request.args.get("source")
    limit       = int(request.args.get("limit", 50))

    query = SuspiciousEvent.query.order_by(SuspiciousEvent.timestamp.desc())
    if severity:    query = query.filter_by(severity=severity)
    if event_type:  query = query.filter_by(event_type=event_type)
    if status:      query = query.filter_by(status=status)
    if target_host: query = query.filter_by(target_host=target_host)
    if source:      query = query.filter_by(source=source)

    return jsonify([e.to_dict() for e in query.limit(limit).all()])


@api.route("/events/open", methods=["GET"])
@jwt_required_with_role("view")
def get_open_events():
    target_host = request.args.get("target_host")
    query = SuspiciousEvent.query.filter(
        SuspiciousEvent.status != "resolved"
    ).order_by(SuspiciousEvent.timestamp.desc())
    if target_host:
        query = query.filter_by(target_host=target_host)
    return jsonify([e.to_dict() for e in query.all()])


@api.route("/events/<int:event_id>/status", methods=["PATCH"])
@jwt_required_with_role("update_status")
def update_event_status(event_id):
    event        = db.session.get(SuspiciousEvent, event_id)
    if not event:
        return jsonify({"error": "Event not found"}), 404

    data         = request.get_json()
    status       = data.get("status")
    current_user = get_jwt_identity()

    if status not in ["open", "investigating", "resolved"]:
        return jsonify({"error": "Invalid status"}), 400

    # ── Ownership enforcement ──────────────────────────────────────────────────
    # If event is being investigated, only the investigator can change its status
    if event.status == "investigating" and event.investigated_by:
        if event.investigated_by != current_user:
            return jsonify({
                "error": f"This event is being investigated by '{event.investigated_by}'"
            }), 403

    # If event is resolved, only the resolver can change its status
    if event.status == "resolved" and event.resolved_by:
        if event.resolved_by != current_user:
            return jsonify({
                "error": f"This event was resolved by '{event.resolved_by}'"
            }), 403

    event.status = status

    if status == "investigating":
        event.investigated_by = current_user
        event.resolved_at     = None
        event.resolved_by     = None
    elif status == "resolved":
        event.resolved_by = current_user
        event.resolved_at = datetime.utcnow()
    elif status == "open":
        event.investigated_by = None
        event.resolved_by     = None
        event.resolved_at     = None

    db.session.commit()
    return jsonify(event.to_dict())


@api.route("/events/<int:event_id>/notes", methods=["PATCH"])
@jwt_required_with_role("update_status")
def update_event_notes(event_id):
    """
    Notes ownership rules:
    - open        → notes not allowed
    - investigating → only investigated_by can write/update
    - resolved    → only resolved_by can write/update, all others read-only
    """
    event        = db.session.get(SuspiciousEvent, event_id)
    if not event:
        return jsonify({"error": "Event not found"}), 404

    current_user = get_jwt_identity()

    if event.status == "open":
        return jsonify({"error": "Notes are only available for events under investigation or resolved"}), 403

    if event.status == "investigating" and event.investigated_by:
        if event.investigated_by != current_user:
            return jsonify({
                "error": f"Only '{event.investigated_by}' can update notes while investigating"
            }), 403

    if event.status == "resolved" and event.resolved_by:
        if event.resolved_by != current_user:
            return jsonify({
                "error": f"Only '{event.resolved_by}' can update notes on a resolved event"
            }), 403

    data        = request.get_json()
    notes       = data.get("notes", "")
    event.notes = notes.strip() if notes else None
    db.session.commit()
    return jsonify(event.to_dict())


# ── Stats ──────────────────────────────────────────────────────────────────────

@api.route("/stats", methods=["GET"])
@jwt_required_with_role("view")
def get_stats():
    target_host = request.args.get("target_host")

    log_query   = LogEntry.query
    event_query = SuspiciousEvent.query

    if target_host:
        log_query   = log_query.filter_by(host=target_host)
        event_query = event_query.filter_by(target_host=target_host)

    return jsonify({
        "total_logs":   log_query.count(),
        "total_events": event_query.count(),
        "open_alerts":  event_query.filter_by(status="open").count(),
        "by_severity": {
            "critical": event_query.filter_by(severity="critical").count(),
            "high":     event_query.filter_by(severity="high").count(),
            "medium":   event_query.filter_by(severity="medium").count(),
            "low":      event_query.filter_by(severity="low").count(),
        },
        "by_type": {
            "brute_force":              event_query.filter_by(event_type="brute_force").count(),
            "brute_force_success":      event_query.filter_by(event_type="brute_force_success").count(),
            "privilege_escalation":     event_query.filter_by(event_type="privilege_escalation").count(),
            "root_login_attempt":       event_query.filter_by(event_type="root_login_attempt").count(),
            "unauthorized_sudo":        event_query.filter_by(event_type="unauthorized_sudo").count(),
            "sensitive_file_access":    event_query.filter_by(event_type="sensitive_file_access").count(),
            "unauthorized_file_access": event_query.filter_by(event_type="unauthorized_file_access").count(),
            "port_scan":                event_query.filter_by(event_type="port_scan").count(),
            "reverse_shell":            event_query.filter_by(event_type="reverse_shell").count(),
            "c2_connection":            event_query.filter_by(event_type="c2_connection").count(),
        }
    })


# ── Timeline ───────────────────────────────────────────────────────────────────

@api.route("/events/timeline", methods=["GET"])
@jwt_required_with_role("view")
def get_timeline():
    target_host = request.args.get("target_host")
    hours       = int(request.args.get("hours", 24))
    since       = datetime.utcnow() - timedelta(hours=hours)

    query = SuspiciousEvent.query.filter(SuspiciousEvent.timestamp >= since)
    if target_host:
        query = query.filter_by(target_host=target_host)

    events  = query.all()
    buckets = {}
    for i in range(hours + 1):
        hour = (since + timedelta(hours=i)).strftime("%Y-%m-%d %H:00")
        buckets[hour] = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}

    for event in events:
        hour = event.timestamp.strftime("%Y-%m-%d %H:00")
        if hour in buckets:
            buckets[hour]["total"]        += 1
            buckets[hour][event.severity] += 1

    return jsonify([{"hour": hour, **counts} for hour, counts in sorted(buckets.items())])


# ── Top Attackers ──────────────────────────────────────────────────────────────

@api.route("/events/top-attackers", methods=["GET"])
@jwt_required_with_role("view")
def get_top_attackers():
    target_host = request.args.get("target_host")
    limit       = int(request.args.get("limit", 10))
    since       = datetime.utcnow() - timedelta(hours=24)

    query = db.session.query(
        SuspiciousEvent.source_ip,
        func.count(SuspiciousEvent.id).label("count")
    ).filter(SuspiciousEvent.source_ip != None, SuspiciousEvent.timestamp >= since)

    if target_host:
        query = query.filter_by(target_host=target_host)

    results = query.group_by(SuspiciousEvent.source_ip)\
                   .order_by(func.count(SuspiciousEvent.id).desc())\
                   .limit(limit).all()

    return jsonify([{"ip": r.source_ip, "count": r.count} for r in results])


# ── Top Targets ────────────────────────────────────────────────────────────────

@api.route("/events/top-targets", methods=["GET"])
@jwt_required_with_role("view")
def get_top_targets():
    target_host = request.args.get("target_host")
    limit       = int(request.args.get("limit", 10))
    since       = datetime.utcnow() - timedelta(hours=24)

    query = db.session.query(
        SuspiciousEvent.username,
        func.count(SuspiciousEvent.id).label("count")
    ).filter(
        SuspiciousEvent.username != None,
        SuspiciousEvent.username != "unset",
        SuspiciousEvent.timestamp >= since
    )

    if target_host:
        query = query.filter_by(target_host=target_host)

    results = query.group_by(SuspiciousEvent.username)\
                   .order_by(func.count(SuspiciousEvent.id).desc())\
                   .limit(limit).all()

    return jsonify([{"username": r.username, "count": r.count} for r in results])


# ── Log Ingestion ──────────────────────────────────────────────────────────────

@api.route("/ingest", methods=["POST"])
@jwt_required_with_role("ingest")
def ingest_logs():
    from services.log_parser import parse
    from services.detector import analyze

    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "Empty filename"}), 400

    processed = saved = alerts = errors = 0

    try:
        content = file.read().decode("utf-8", errors="ignore")
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            processed += 1
            try:
                parsed = parse(line)
                if not parsed:
                    continue
                entry = LogEntry(
                    timestamp = parsed["timestamp"],
                    host      = parsed["host"],
                    process   = parsed["process"],
                    pid       = parsed["pid"],
                    message   = parsed["message"],
                    log_type  = parsed["log_type"],
                    raw       = parsed["raw"],
                    source    = "historical",
                )
                db.session.add(entry)
                db.session.flush()
                saved += 1
                suspicious = analyze(parsed)
                if suspicious:
                    se = SuspiciousEvent(
                        timestamp       = suspicious["timestamp"],
                        event_type      = suspicious["event_type"],
                        severity        = suspicious["severity"],
                        source_ip       = suspicious.get("source_ip"),
                        target_host     = suspicious.get("target_host"),
                        username        = suspicious.get("username"),
                        description     = suspicious["description"],
                        raw_log_id      = entry.id,
                        status          = "open",
                        source          = "historical",
                        mitre_technique = suspicious.get("mitre_technique"),
                        mitre_tactic    = suspicious.get("mitre_tactic"),
                    )
                    db.session.add(se)
                    alerts += 1
            except Exception:
                errors += 1
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

    return jsonify({"status": "complete", "processed": processed,
                    "saved": saved, "alerts": alerts, "errors": errors})


# ── Hosts ──────────────────────────────────────────────────────────────────────

@api.route("/hosts", methods=["GET"])
@jwt_required_with_role("view")
def get_hosts():
    hosts = db.session.query(LogEntry.host).distinct().all()
    return jsonify([h[0] for h in hosts if h[0]])


# ── Reload Rules ───────────────────────────────────────────────────────────────

@api.route("/rules/reload", methods=["POST"])
@jwt_required_with_role("reload_rules")
def reload_rules():
    from services.config_loader import reload_rules
    reload_rules()
    return jsonify({"status": "rules reloaded"})