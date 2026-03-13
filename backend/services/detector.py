from collections import defaultdict
from datetime import datetime, timedelta
from services.config_loader import get_rule, is_enabled
import re

_audit_events  = {}
_net_events    = {}   # correlate SYSCALL + SOCKADDR by event_id

# In-memory trackers
_file_access       = defaultdict(list)
_failed_attempts   = defaultdict(list)
_successful_logins = defaultdict(list)
_sudo_failures     = defaultdict(list)
_unauthorized_sudo = defaultdict(list)
_port_scan         = defaultdict(set)   # key: "auid:exe" → set of dst_ports
_port_scan_times   = defaultdict(list)  # key: "auid:exe" → list of timestamps
_c2_connections    = defaultdict(list)  # key: "auid:dst_ip" → list of timestamps


def _SENSITIVE_FILES():
    return get_rule("sensitive_file_access.paths", [
        "/etc/passwd", "/etc/shadow", "/etc/sudoers",
        "/etc/ssh/sshd_config", "/.ssh/authorized_keys", "/root",
    ])

def _EXCLUDED_PATHS():
    return get_rule("unauthorized_file_access.excluded_paths", [
        "/sys/", "/proc/", "/dev/", "/run/",
    ])

# Internal IPs to exclude from network alerts (RFC1918 + loopback)
INTERNAL_PREFIXES = ["127.", "10.", "192.168.", "172.16.", "172.17.",
                     "172.18.", "172.19.", "172.20.", "172.21.", "172.22.",
                     "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
                     "172.28.", "172.29.", "172.30.", "172.31.", "0.0.0.0"]

def _is_internal(ip: str) -> bool:
    return any(ip.startswith(p) for p in INTERNAL_PREFIXES)


def analyze(parsed_entry: dict) -> dict | None:
    if not parsed_entry:
        return None

    fields   = parsed_entry.get("parsed", {})
    event    = fields.get("event")
    log_type = parsed_entry.get("log_type")

    # ── SSH ────────────────────────────────────────────────────────────────
    if event in ("ssh_failed_login", "ssh_invalid_user"):
        if fields.get("username") == "root" and is_enabled("root_login"):
            return _make_event(
                event_type   = "root_login_attempt",
                severity     = get_rule("root_login.severity", "high"),
                source_ip    = fields.get("src_ip"),
                target_host  = parsed_entry.get("host"),
                username     = "root",
                description  = (
                    f"SSH login attempt targeting root account from "
                    f"{fields.get('src_ip')} — root login is disabled"
                ),
                parsed_entry = parsed_entry,
            )
        if is_enabled("brute_force"):
            return _check_brute_force(parsed_entry, fields)

    if event == "ssh_accepted_login":
        return _check_successful_login(parsed_entry, fields)

    # ── Privilege Escalation ───────────────────────────────────────────────
    if event == "sudo_command" and is_enabled("privilege_escalation"):
        return _check_privilege_escalation(parsed_entry, fields)

    if event == "sudo_auth_failure":
        if "sudo" in parsed_entry.get("process", "") and is_enabled("sudo_brute_force"):
            return _check_sudo_failures(parsed_entry, fields)

    if event == "sudo_not_allowed" and is_enabled("unauthorized_sudo"):
        return _check_unauthorized_sudo(parsed_entry, fields)

    # ── File Access + Network ──────────────────────────────────────────────
    if log_type in ("file_access", "network"):
        audit_type = fields.get("audit_type")
        event_id   = fields.get("event_id")

        if audit_type == "SYSCALL" and event_id:
            # Store SYSCALL info — used by both file access and network detectors
            _audit_events[event_id] = {
                "auid":      fields.get("auid"),
                "command":   fields.get("command"),
                "exe":       fields.get("exe"),
                "audit_key": fields.get("audit_key"),
                "timestamp": parsed_entry["timestamp"],
                "host":      parsed_entry.get("host"),
                "cwd":       None,
            }
            return None

        if audit_type == "CWD" and event_id:
            if event_id in _audit_events:
                cwd = re.search(r'cwd="([^"]+)"', parsed_entry["message"])
                if cwd:
                    _audit_events[event_id]["cwd"] = cwd.group(1)
            return None

        if audit_type == "SOCKADDR" and event_id:
            # Network connection — correlate with SYSCALL info
            dst_ip   = fields.get("dst_ip", "")
            dst_port = fields.get("dst_port")
            family   = fields.get("family", "")

            # Skip unix sockets, empty, or unresolved
            if not dst_ip or not dst_port or not family:
                return None

            syscall_info = _audit_events.get(event_id, {})
            auid         = syscall_info.get("auid")
            exe          = syscall_info.get("exe", "")
            command      = syscall_info.get("command", "")

            merged = dict(parsed_entry)
            merged["parsed"] = {
                "event":    "network_connect",
                "dst_ip":   dst_ip,
                "dst_port": dst_port,
                "family":   family,
                "auid":     auid,
                "exe":      exe,
                "command":  command,
                "event_id": event_id,
            }

            return _check_network(merged, merged["parsed"])

        if audit_type == "PATH" and event_id:
            syscall_info = _audit_events.pop(event_id, {})
            filepath     = fields.get("filepath", "")
            audit_key    = fields.get("audit_key") or syscall_info.get("audit_key")
            auid         = syscall_info.get("auid")
            command      = syscall_info.get("command")
            cwd          = syscall_info.get("cwd", "")

            if filepath and not filepath.startswith("/"):
                filepath = f"{cwd}/{filepath}" if cwd else filepath

            merged = dict(parsed_entry)
            merged["parsed"] = {
                "event":     "file_access",
                "filepath":  filepath,
                "audit_key": audit_key,
                "auid":      auid,
                "command":   command,
                "event_id":  event_id,
            }

            if audit_key == "unauthorized_access" and is_enabled("unauthorized_file_access"):
                return _check_unauthorized_file_access(merged, merged["parsed"])
            if is_enabled("sensitive_file_access"):
                return _check_file_access(merged, merged["parsed"])

    return None


# ── Detection helpers ──────────────────────────────────────────────────────────

def _check_brute_force(parsed_entry, fields):
    ip       = fields.get("src_ip")
    username = fields.get("username")
    now      = parsed_entry["timestamp"]
    key      = f"{ip}:{username}"
    window   = get_rule("brute_force.window_seconds", 60)

    _failed_attempts[key].append(now)
    window_start = now - timedelta(seconds=window)
    _failed_attempts[key] = [t for t in _failed_attempts[key] if t >= window_start]
    count = len(_failed_attempts[key])

    t_medium   = get_rule("brute_force.thresholds.medium", 5)
    t_high     = get_rule("brute_force.thresholds.high", 10)
    t_critical = get_rule("brute_force.thresholds.critical", 20)

    if count == t_medium:      severity = "medium"
    elif count == t_high:      severity = "high"
    elif count == t_critical:  severity = "critical"
    else:                      return None

    return _make_event(
        event_type   = "brute_force",
        severity     = severity,
        source_ip    = ip,
        target_host  = parsed_entry.get("host"),
        username     = username,
        description  = (
            f"Brute force attack: {count} failed SSH attempts "
            f"from {ip} targeting '{username}' in {window}s"
        ),
        parsed_entry = parsed_entry,
    )


def _check_successful_login(parsed_entry, fields):
    ip       = fields.get("src_ip")
    username = fields.get("username")
    now      = parsed_entry["timestamp"]
    key      = f"{ip}:{username}"
    window   = get_rule("brute_force.window_seconds", 60)

    recent_failures = [
        t for t in _failed_attempts.get(key, [])
        if t >= now - timedelta(seconds=window)
    ]
    _successful_logins[ip].append(now)

    if recent_failures:
        return _make_event(
            event_type   = "brute_force_success",
            severity     = "critical",
            source_ip    = ip,
            target_host  = parsed_entry.get("host"),
            username     = username,
            description  = (
                f"Possible brute force success: '{username}' logged in from {ip} "
                f"after {len(recent_failures)} failed attempts"
            ),
            parsed_entry = parsed_entry,
        )

    return _make_event(
        event_type   = "ssh_login_success",
        severity     = "low",
        source_ip    = ip,
        target_host  = parsed_entry.get("host"),
        username     = username,
        description  = f"Successful SSH login for '{username}' from {ip}",
        parsed_entry = parsed_entry,
    )


def _check_privilege_escalation(parsed_entry, fields):
    command  = fields.get("command", "")
    username = fields.get("username")
    run_as   = fields.get("run_as")

    if run_as != "root":
        return None

    pe = "privilege_escalation"

    if is_enabled(f"{pe}.shell_spawn"):
        cmds = get_rule(f"{pe}.shell_spawn.commands",
            ["/bin/bash", "/bin/sh", "/bin/zsh", "sudo su", "sudo -i", "sudo -s"])
        if any(c in command for c in cmds):
            return _make_event(
                event_type   = "privilege_escalation",
                severity     = get_rule(f"{pe}.shell_spawn.severity", "critical"),
                source_ip    = None,
                target_host  = parsed_entry.get("host"),
                username     = username,
                description  = f"Root shell spawned by '{username}': {command}",
                parsed_entry = parsed_entry,
            )

    if is_enabled(f"{pe}.sudoers_modification"):
        patterns = get_rule(f"{pe}.sudoers_modification.patterns", ["visudo", "/etc/sudoers"])
        if any(p in command for p in patterns):
            return _make_event(
                event_type   = "privilege_escalation",
                severity     = get_rule(f"{pe}.sudoers_modification.severity", "critical"),
                source_ip    = None,
                target_host  = parsed_entry.get("host"),
                username     = username,
                description  = f"Sudoers modified by '{username}': {command}",
                parsed_entry = parsed_entry,
            )

    if is_enabled(f"{pe}.group_modification"):
        groups = get_rule(f"{pe}.group_modification.groups", ["sudo", "admin", "wheel"])
        if "usermod" in command and any(g in command for g in groups):
            return _make_event(
                event_type   = "privilege_escalation",
                severity     = get_rule(f"{pe}.group_modification.severity", "critical"),
                source_ip    = None,
                target_host  = parsed_entry.get("host"),
                username     = username,
                description  = f"User added to privileged group by '{username}': {command}",
                parsed_entry = parsed_entry,
            )

    if is_enabled(f"{pe}.user_creation"):
        cmds = get_rule(f"{pe}.user_creation.commands", ["useradd", "adduser"])
        if any(c in command for c in cmds):
            return _make_event(
                event_type   = "privilege_escalation",
                severity     = get_rule(f"{pe}.user_creation.severity", "high"),
                source_ip    = None,
                target_host  = parsed_entry.get("host"),
                username     = username,
                description  = f"New user created by '{username}': {command}",
                parsed_entry = parsed_entry,
            )

    if is_enabled(f"{pe}.password_change") and "passwd" in command:
        parts = command.strip().split()
        if len(parts) > 1 and parts[-1] != username:
            return _make_event(
                event_type   = "privilege_escalation",
                severity     = get_rule(f"{pe}.password_change.severity", "high"),
                source_ip    = None,
                target_host  = parsed_entry.get("host"),
                username     = username,
                description  = f"'{username}' changed password for '{parts[-1]}': {command}",
                parsed_entry = parsed_entry,
            )

    return None


def _check_sudo_failures(parsed_entry, fields):
    username  = fields.get("username")
    now       = parsed_entry["timestamp"]
    window    = get_rule("sudo_brute_force.window_seconds", 60)
    threshold = get_rule("sudo_brute_force.threshold", 3)

    _sudo_failures[username].append(now)
    _sudo_failures[username] = [
        t for t in _sudo_failures[username]
        if t >= now - timedelta(seconds=window)
    ]
    count = len(_sudo_failures[username])

    if count >= threshold:
        return _make_event(
            event_type   = "sudo_brute_force",
            severity     = get_rule("sudo_brute_force.severity", "high"),
            source_ip    = None,
            target_host  = parsed_entry.get("host"),
            username     = username,
            description  = (
                f"Multiple sudo failures ({count}) for '{username}' in {window}s"
            ),
            parsed_entry = parsed_entry,
        )
    return None


def _check_unauthorized_sudo(parsed_entry, fields):
    username = fields.get("username")
    now      = parsed_entry["timestamp"]
    window   = get_rule("unauthorized_sudo.dedup_window_seconds", 10)

    recent = [
        t for t in _unauthorized_sudo.get(username, [])
        if t >= now - timedelta(seconds=window)
    ]
    if recent:
        _unauthorized_sudo[username] = recent
        return None

    _unauthorized_sudo[username] = recent + [now]

    return _make_event(
        event_type   = "unauthorized_sudo",
        severity     = get_rule("unauthorized_sudo.severity", "medium"),
        source_ip    = None,
        target_host  = parsed_entry.get("host"),
        username     = username,
        description  = f"Unauthorized sudo attempt by '{username}' — not in sudoers",
        parsed_entry = parsed_entry,
    )


def _check_file_access(parsed_entry, fields):
    filepath = fields.get("filepath", "")
    now      = parsed_entry["timestamp"]
    auid     = fields.get("auid")
    command  = fields.get("command")
    window   = get_rule("sensitive_file_access.dedup_window_seconds", 10)

    if not filepath or not auid or auid == "unset":
        return None

    for sensitive in _SENSITIVE_FILES():
        if sensitive in filepath:
            recent = [
                t for t in _file_access.get(filepath, [])
                if t >= now - timedelta(seconds=window)
            ]
            if recent:
                _file_access[filepath] = recent
                return None

            _file_access[filepath] = recent + [now]

            return _make_event(
                event_type   = "sensitive_file_access",
                severity     = get_rule("sensitive_file_access.severity", "high"),
                source_ip    = None,
                target_host  = parsed_entry.get("host"),
                username     = auid,
                description  = (
                    f"Sensitive file '{filepath}' accessed by '{auid}' using '{command}'"
                ),
                parsed_entry = parsed_entry,
            )
    return None


def _check_unauthorized_file_access(parsed_entry, fields):
    filepath = fields.get("filepath", "")
    auid     = fields.get("auid")
    command  = fields.get("command")
    now      = parsed_entry["timestamp"]
    window   = get_rule("unauthorized_file_access.dedup_window_seconds", 30)

    if not filepath or not auid or auid == "unset":
        return None
    if any(filepath.startswith(p) for p in _EXCLUDED_PATHS()):
        return None

    event_id = fields.get("event_id", "")
    key      = f"{auid}:{filepath}:{event_id}"
    recent   = [
        t for t in _file_access.get(key, [])
        if t >= now - timedelta(seconds=window)
    ]
    if recent:
        _file_access[key] = recent
        return None

    _file_access[key] = recent + [now]

    return _make_event(
        event_type   = "unauthorized_file_access",
        severity     = get_rule("unauthorized_file_access.severity", "medium"),
        source_ip    = None,
        target_host  = parsed_entry.get("host"),
        username     = auid,
        description  = f"Permission denied: '{auid}' tried to access '{filepath}' using '{command}'",
        parsed_entry = parsed_entry,
    )


def _check_network(parsed_entry, fields):
    dst_ip   = fields.get("dst_ip", "")
    dst_port = fields.get("dst_port")
    auid     = fields.get("auid")
    exe      = fields.get("exe", "unknown")
    command  = fields.get("command", exe)
    now      = parsed_entry["timestamp"]
    host     = parsed_entry.get("host")

    if not dst_ip or not dst_port:
        return None

    # Skip unauthenticated system processes
    if not auid or auid == "unset":
        return None

    # ── Port Scan Detection ──────────────────────────────────────────────
    if is_enabled("port_scan"):
        window    = get_rule("port_scan.window_seconds", 10)
        threshold = get_rule("port_scan.port_threshold", 15)
        key       = f"{auid}:{exe}"

        # Track unique ports contacted within window
        _port_scan_times[key].append(now)
        _port_scan_times[key] = [
            t for t in _port_scan_times[key]
            if t >= now - timedelta(seconds=window)
        ]

        # Reset port set when window expires
        if len(_port_scan_times[key]) == 1:
            _port_scan[key] = set()

        _port_scan[key].add(dst_port)
        unique_ports = len(_port_scan[key])

        if unique_ports == threshold:
            return _make_event(
                event_type   = "port_scan",
                severity     = get_rule("port_scan.severity", "high"),
                source_ip    = None,
                target_host  = host,
                username     = auid,
                description  = (
                    f"Port scan detected: '{command}' contacted {unique_ports} unique ports "
                    f"within {window}s"
                ),
                parsed_entry = parsed_entry,
            )

    # ── Reverse Shell Detection ──────────────────────────────────────────
    if is_enabled("reverse_shell"):
        shell_exes  = get_rule("reverse_shell.shell_executables",
            ["/bin/bash", "/bin/sh", "/bin/zsh", "python", "perl", "ruby", "nc", "ncat", "netcat"])
        suspicious  = any(s in exe for s in shell_exes)

        if suspicious and not _is_internal(dst_ip):
            return _make_event(
                event_type   = "reverse_shell",
                severity     = get_rule("reverse_shell.severity", "critical"),
                source_ip    = dst_ip,
                target_host  = host,
                username     = auid,
                description  = (
                    f"Possible reverse shell: '{exe}' made outbound connection "
                    f"to {dst_ip}:{dst_port}"
                ),
                parsed_entry = parsed_entry,
            )

    # ── C2 Beaconing Detection ───────────────────────────────────────────
    if is_enabled("c2_detection") and not _is_internal(dst_ip):
        window    = get_rule("c2_detection.window_seconds", 300)
        threshold = get_rule("c2_detection.connection_threshold", 10)
        key       = f"{auid}:{dst_ip}"

        _c2_connections[key].append(now)
        _c2_connections[key] = [
            t for t in _c2_connections[key]
            if t >= now - timedelta(seconds=window)
        ]
        count = len(_c2_connections[key])

        if count == threshold:
            return _make_event(
                event_type   = "c2_connection",
                severity     = get_rule("c2_detection.severity", "critical"),
                source_ip    = dst_ip,
                target_host  = host,
                username     = auid,
                description  = (
                    f"Possible C2 beaconing: '{command}' made {count} connections "
                    f"to {dst_ip} within {window}s"
                ),
                parsed_entry = parsed_entry,
            )

    return None


# Maps event_type to config key for MITRE lookup
_MITRE_MAP = {
    "brute_force":              "brute_force",
    "brute_force_success":      "brute_force",
    "root_login_attempt":       "root_login",
    "privilege_escalation":     "privilege_escalation",
    "unauthorized_sudo":        "unauthorized_sudo",
    "sudo_brute_force":         "sudo_brute_force",
    "sensitive_file_access":    "sensitive_file_access",
    "unauthorized_file_access": "unauthorized_file_access",
    "port_scan":                "port_scan",
    "reverse_shell":            "reverse_shell",
    "c2_connection":            "c2_detection",
    "ssh_login_success":        None,
}

def _make_event(event_type, severity, source_ip, target_host, username, description, parsed_entry):
    rule_key        = _MITRE_MAP.get(event_type)
    mitre_technique = get_rule(f"{rule_key}.mitre_technique") if rule_key else None
    mitre_tactic    = get_rule(f"{rule_key}.mitre_tactic")    if rule_key else None

    return {
        "event_type":      event_type,
        "severity":        severity,
        "source_ip":       source_ip,
        "target_host":     target_host,
        "username":        username,
        "description":     description,
        "timestamp":       parsed_entry["timestamp"],
        "mitre_technique": mitre_technique,
        "mitre_tactic":    mitre_tactic,
    }