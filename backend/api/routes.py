from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from models.log_entry import LogEntry, SuspiciousEvent, EventAuditLog
from models.user import User
from database.db import db
from datetime import datetime, timedelta
from sqlalchemy import func
from services.auth import jwt_required_with_role

api = Blueprint("api", __name__, url_prefix="/api")


def _is_admin(username):
    """Check if a username belongs to an admin user."""
    user = User.query.filter_by(username=username, is_active=True).first()
    return user and user.role == "admin"


def _audit(event_id, action, performed_by, details=None):
    """Append an immutable audit log entry."""
    log = EventAuditLog(
        event_id     = event_id,
        action       = action,
        performed_by = performed_by,
        details      = details,
    )
    db.session.add(log)
    # No commit here — caller commits after all changes


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
    admin        = _is_admin(current_user)

    if status not in ["open", "investigating", "resolved"]:
        return jsonify({"error": "Invalid status"}), 400

    # ── Ownership enforcement ──────────────────────────────────────────────
    if event.status == "open" and event.assigned_to:
        if event.assigned_to != current_user and not admin:
            return jsonify({
                "error": f"This event is assigned to '{event.assigned_to}'"
            }), 403

    if event.status == "investigating" and event.investigated_by:
        if event.investigated_by != current_user:
            if admin and status == "resolved":
                return jsonify({
                    "error": f"Cannot resolve on behalf of '{event.investigated_by}' — reassign first"
                }), 403
            elif not admin:
                return jsonify({
                    "error": f"Being investigated by '{event.investigated_by}'"
                }), 403

    if event.status == "resolved" and event.resolved_by:
        if event.resolved_by != current_user and not admin:
            return jsonify({
                "error": "Resolved events can only be reopened by the resolver or an admin"
            }), 403

    # ── Apply status + audit ───────────────────────────────────────────────
    prev_status = event.status
    event.status = status

    if status == "investigating":
        event.investigated_by = current_user
        event.resolved_at     = None
        event.resolved_by     = None
        event.assigned_to     = None
        _audit(event_id, "investigating", current_user,
               f"Started investigation (was: {prev_status})")

    elif status == "resolved":
        event.resolved_by = current_user
        event.resolved_at = datetime.utcnow()
        _audit(event_id, "resolved", current_user, "Event resolved")

    elif status == "open":
        # Capture who had it before clearing — preserve in audit details
        prev_actor = event.resolved_by or event.investigated_by
        detail     = f"Reopened from '{prev_status}'"
        if prev_actor:
            detail += f" (previously handled by '{prev_actor}')"
        _audit(event_id, "reopened", current_user, detail)
        event.investigated_by = None
        event.resolved_by     = None
        event.resolved_at     = None
        event.notes           = None
        event.reopened_at     = datetime.utcnow()

    db.session.commit()
    return jsonify(event.to_dict())


@api.route("/events/<int:event_id>/assign", methods=["PATCH"])
@jwt_required_with_role("manage_users")
def assign_event(event_id):
    event = db.session.get(SuspiciousEvent, event_id)
    if not event:
        return jsonify({"error": "Event not found"}), 404

    if event.status == "resolved":
        return jsonify({"error": "Use the reopen endpoint for resolved events"}), 400

    data        = request.get_json()
    assigned_to = data.get("assigned_to")
    current_user = get_jwt_identity()

    if assigned_to:
        assignee = User.query.filter_by(username=assigned_to, is_active=True).first()
        if not assignee:
            return jsonify({"error": f"User '{assigned_to}' not found or inactive"}), 404

    # Force reassigning an investigating event — reset to open
    if event.status == "investigating":
        prev_investigator     = event.investigated_by
        event.status          = "open"
        event.investigated_by = None
        event.reopened_at     = datetime.utcnow()
        _audit(event_id, "force_reassigned", current_user,
               f"Force reassigned from '{prev_investigator}' → '{assigned_to or 'unassigned'}'")
    else:
        prev = event.assigned_to
        action  = "reassigned" if prev else "assigned"
        details = f"Assigned to '{assigned_to}'" if assigned_to else "Assignment removed"
        if prev and assigned_to:
            details = f"Reassigned from '{prev}' → '{assigned_to}'"
        _audit(event_id, action, current_user, details)

    event.assigned_to = assigned_to
    db.session.commit()
    return jsonify(event.to_dict())


@api.route("/events/<int:event_id>/notes", methods=["PATCH"])
@jwt_required_with_role("update_status")
def update_event_notes(event_id):
    event        = db.session.get(SuspiciousEvent, event_id)
    if not event:
        return jsonify({"error": "Event not found"}), 404

    current_user = get_jwt_identity()
    admin        = _is_admin(current_user)

    if event.status == "open":
        return jsonify({"error": "Notes only available for events under investigation or resolved"}), 403

    if event.status == "investigating" and event.investigated_by:
        if event.investigated_by != current_user and not admin:
            return jsonify({
                "error": f"Only '{event.investigated_by}' can update notes while investigating"
            }), 403

    if event.status == "resolved" and event.resolved_by:
        if event.resolved_by != current_user and not admin:
            return jsonify({
                "error": f"Only '{event.resolved_by}' can update notes on a resolved event"
            }), 403

    data        = request.get_json()
    notes       = data.get("notes", "")
    had_notes   = bool(event.notes)
    event.notes = notes.strip() if notes else None

    action  = "note_updated" if had_notes else "note_added"
    preview = (notes or "")[:80] + ("..." if len(notes or "") > 80 else "")
    _audit(event_id, action, current_user,
           f"Note {'updated' if had_notes else 'added'}: \"{preview}\"" if preview else "Note cleared")

    db.session.commit()
    return jsonify(event.to_dict())


# ── Audit Log ──────────────────────────────────────────────────────────────────

@api.route("/events/<int:event_id>/audit", methods=["GET"])
@jwt_required_with_role("view")
def get_event_audit(event_id):
    """Return the full audit trail for a specific event."""
    event = db.session.get(SuspiciousEvent, event_id)
    if not event:
        return jsonify({"error": "Event not found"}), 404

    logs = EventAuditLog.query\
        .filter_by(event_id=event_id)\
        .order_by(EventAuditLog.timestamp.asc())\
        .all()

    return jsonify([l.to_dict() for l in logs])


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
                    db.session.flush()
                    # Use event timestamp not utcnow() so audit matches detection time
                    log = EventAuditLog(
                        event_id     = se.id,
                        timestamp    = se.timestamp,
                        action       = "created",
                        performed_by = "system",
                        details      = f"Auto-detected: {suspicious['event_type']} ({suspicious['severity']})",
                    )
                    db.session.add(log)
                    alerts += 1
            except Exception:
                errors += 1
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

    return jsonify({"status": "complete", "processed": processed,
                    "saved": saved, "alerts": alerts, "errors": errors})



# ── Single Log Entry ──────────────────────────────────────────────────────────

@api.route("/logs/<int:log_id>", methods=["GET"])
@jwt_required_with_role("view")
def get_log_entry(log_id):
    """Fetch a single raw log entry by ID."""
    entry = db.session.get(LogEntry, log_id)
    if not entry:
        return jsonify({"error": "Log entry not found"}), 404
    return jsonify(entry.to_dict())


# ── Related Events ────────────────────────────────────────────────────────────

@api.route("/events/<int:event_id>/related", methods=["GET"])
@jwt_required_with_role("view")
def get_related_events(event_id):
    """
    Return events related to the given event by source_ip or username
    within the last 7 days, excluding the event itself.
    """
    event = db.session.get(SuspiciousEvent, event_id)
    if not event:
        return jsonify({"error": "Event not found"}), 404

    since = event.timestamp - timedelta(days=7)
    related = []

    # Related by source IP
    if event.source_ip:
        by_ip = SuspiciousEvent.query.filter(
            SuspiciousEvent.id        != event_id,
            SuspiciousEvent.source_ip == event.source_ip,
            SuspiciousEvent.timestamp >= since,
        ).order_by(SuspiciousEvent.timestamp.desc()).limit(10).all()
        for e in by_ip:
            d = e.to_dict()
            d['relation'] = 'source_ip'
            related.append(d)

    # Related by username (excluding already added by IP)
    if event.username and event.username != 'unset':
        existing_ids = [r['id'] for r in related]
        q = SuspiciousEvent.query.filter(
            SuspiciousEvent.id       != event_id,
            SuspiciousEvent.username == event.username,
            SuspiciousEvent.timestamp >= since,
        )
        if existing_ids:
            q = q.filter(SuspiciousEvent.id.notin_(existing_ids))
        for e in q.order_by(SuspiciousEvent.timestamp.desc()).limit(10).all():
            d = e.to_dict()
            d['relation'] = 'username'
            related.append(d)

    related.sort(key=lambda x: x['timestamp'], reverse=True)
    return jsonify(related[:15])

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