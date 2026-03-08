from collections import defaultdict
from datetime import datetime, timedelta
from config import Config

#Track failed ssh logins
_failed_attempts = defaultdict(list)

#Track suscess ssh logins
_successful_logins = defaultdict(list)

# Track sudo failures per user
_sudo_failures = defaultdict(list)

# Sensitive files to watch for access alerts
SENSITIVE_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/.ssh/authorized_keys",
    "/root",
]

_unauthorized_sudo = defaultdict(list)


def analyze(parsed_entry: dict) -> dict | None:
    """
    Analyze a parsed log entry and return a suspicious event dict if
    a threat is detected, otherwise return None.
    """
    if not parsed_entry:
        return None

    fields   = parsed_entry.get("parsed", {})
    event    = fields.get("event")
    log_type = parsed_entry.get("log_type")

    # ── SSH Brute Force Detection ──────────────────────────────────────────
    if event == "ssh_failed_login" or event == "ssh_invalid_user":
        # Flag root login attempts
        if fields.get("username") == "root":
            return _make_event(
                event_type  = "root_login_attempt",
                severity    = "high",
                source_ip   = fields.get("src_ip"),
                username    = "root",
                description = (
                    f"SSH login attempt targeting root account from "
                    f"{fields.get('src_ip')} — root login is disabled"
                ),
                parsed_entry = parsed_entry,
            )
        return _check_brute_force(parsed_entry, fields)
    
    if event == "ssh_accepted_login":
        return _check_successful_login(parsed_entry, fields)

    # ── SSH Invalid User ───────────────────────────────────────────────────
    if event == "ssh_invalid_user":
        return _make_event(
            event_type  = "invalid_user_attempt",
            severity    = "medium",
            source_ip   = fields.get("src_ip"),
            username    = fields.get("username"),
            description = (
                f"SSH login attempt with non-existent user '{fields.get('username')}' "
                f"from {fields.get('src_ip')}"
            ),
            parsed_entry = parsed_entry,
        )

    # ── Privilege Escalation (sudo) ────────────────────────────────────────
    if event == "sudo_command":
        return _check_privilege_escalation(parsed_entry, fields)

    if event == "sudo_auth_failure":
        if "sudo" in parsed_entry.get("process", ""):
            return _check_sudo_failures(parsed_entry, fields)
        
    if event == "sudo_not_allowed":
        username = fields.get("username")
        now      = parsed_entry["timestamp"]

        # Deduplicate — only alert once per user per 10 seconds
        recent = _unauthorized_sudo.get(username, [])
        window = now - timedelta(seconds=10)
        recent = [t for t in recent if t >= window]

        if recent:
            # Already alerted for this user recently — skip
            _unauthorized_sudo[username] = recent
            return None

        _unauthorized_sudo[username] = recent + [now]

        return _make_event(
            event_type  = "unauthorized_sudo",
            severity    = "medium",
            source_ip   = None,
            username    = username,
            description = (
                f"Unauthorized sudo attempt by '{username}' "
                f"— user is not in sudoers file"
            ),
            parsed_entry = parsed_entry,
        )

    # ── Sensitive File Access ──────────────────────────────────────────────
    if event == "file_access":
        return _check_file_access(parsed_entry, fields)

    return None


# ── Internal detection helpers ─────────────────────────────────────────────
def _check_brute_force(parsed_entry, fields):
    ip       = fields.get("src_ip")
    username = fields.get("username")
    now      = parsed_entry["timestamp"]

    # Key is IP+username combination
    key = f"{ip}:{username}"

    # Add this attempt to the sliding window
    _failed_attempts[key].append(now)

    # Remove attempts outside the time window
    window_start = now - timedelta(seconds=Config.BRUTE_FORCE_WINDOW)
    _failed_attempts[key] = [t for t in _failed_attempts[key] if t >= window_start]

    count = len(_failed_attempts[key])

    # Only alert at threshold crossings to avoid duplicate alerts
    if count == Config.BRUTE_FORCE_THRESHOLD:
        severity = "medium"
    elif count == 10:
        severity = "high"
    elif count == 20:
        severity = "critical"
    else:
        return None

    return _make_event(
        event_type  = "brute_force",
        severity    = severity,
        source_ip   = ip,
        username    = username,
        description = (
            f"Brute force attack detected: {count} failed SSH login attempts "
            f"from {ip} targeting user '{username}' "
            f"in the last {Config.BRUTE_FORCE_WINDOW}s"
        ),
        parsed_entry = parsed_entry,
    )


def _check_successful_login(parsed_entry, fields):
    ip       = fields.get("src_ip")
    username = fields.get("username")
    now      = parsed_entry["timestamp"]

    # Check failures for this exact IP+username combination
    key          = f"{ip}:{username}"
    window_start = now - timedelta(seconds=Config.BRUTE_FORCE_WINDOW)
    recent_failures = [t for t in _failed_attempts.get(key, []) if t >= window_start]
    failure_count   = len(recent_failures)

    # Always log successful logins
    _successful_logins[ip].append(now)

    if failure_count > 0:
        # Successful login after failures for same IP+username — brute force success
        return _make_event(
            event_type  = "brute_force_success",
            severity    = "critical",
            source_ip   = ip,
            username    = username,
            description = (
                f"Possible successful brute force: '{username}' logged in from {ip} "
                f"after {failure_count} failed attempts targeting the same account"
            ),
            parsed_entry = parsed_entry,
        )

    # Clean successful login — low severity, informational
    return _make_event(
        event_type  = "ssh_login_success",
        severity    = "low",
        source_ip   = ip,
        username    = username,
        description = f"Successful SSH login for '{username}' from {ip}",
        parsed_entry = parsed_entry,
    )



def _check_privilege_escalation(parsed_entry, fields):
    command  = fields.get("command", "")
    username = fields.get("username")
    run_as   = fields.get("run_as")

    if run_as != "root":
        return None

    # ── Spawning a root shell ─────────────────────────────────────────────
    shell_spawn = ["/bin/bash", "/bin/sh", "/bin/zsh", "sudo su", "sudo -i", "sudo -s"]
    if any(cmd in command for cmd in shell_spawn):
        return _make_event(
            event_type  = "privilege_escalation",
            severity    = "critical",
            source_ip   = None,
            username    = username,
            description = (
                f"Root shell spawned by '{username}': {command}"
            ),
            parsed_entry = parsed_entry,
        )

    # ── Sudoers modification ──────────────────────────────────────────────
    sudoers_commands = ["visudo", "/etc/sudoers"]
    if any(cmd in command for cmd in sudoers_commands):
        return _make_event(
            event_type  = "privilege_escalation",
            severity    = "critical",
            source_ip   = None,
            username    = username,
            description = (
                f"Sudoers file modified by '{username}': {command}"
            ),
            parsed_entry = parsed_entry,
        )

    # ── Adding user to sudo/admin group ───────────────────────────────────
    if "usermod" in command and any(g in command for g in ["sudo", "admin", "wheel"]):
        return _make_event(
            event_type  = "privilege_escalation",
            severity    = "critical",
            source_ip   = None,
            username    = username,
            description = (
                f"User added to privileged group by '{username}': {command}"
            ),
            parsed_entry = parsed_entry,
        )

    # ── New user creation ─────────────────────────────────────────────────
    if any(cmd in command for cmd in ["useradd", "adduser"]):
        return _make_event(
            event_type  = "privilege_escalation",
            severity    = "high",
            source_ip   = None,
            username    = username,
            description = (
                f"New user created by '{username}': {command}"
            ),
            parsed_entry = parsed_entry,
        )

    # ── Changing another user's password ─────────────────────────────────
    if "passwd" in command:
        # Extract the target username from the command
        parts = command.strip().split()
        # passwd alone means changing own password — not suspicious
        # passwd <username> means changing someone else's — suspicious
        if len(parts) > 1:
            target = parts[-1]
            if target != username:
                return _make_event(
                    event_type  = "privilege_escalation",
                    severity    = "high",
                    source_ip   = None,
                    username    = username,
                    description = (
                        f"'{username}' changed password for another user '{target}': {command}"
                    ),
                    parsed_entry = parsed_entry,
                )

    return None

def _check_sudo_failures(parsed_entry, fields):
    username = fields.get("username")
    now      = parsed_entry["timestamp"]

    _sudo_failures[username].append(now)
    window_start = now - timedelta(seconds=Config.BRUTE_FORCE_WINDOW)
    _sudo_failures[username] = [t for t in _sudo_failures[username] if t >= window_start]

    count = len(_sudo_failures[username])
    if count >= 3:
        return _make_event(
            event_type  = "sudo_brute_force",
            severity    = "high",
            source_ip   = None,
            username    = username,
            description = (
                f"Multiple sudo authentication failures ({count}) for user '{username}' "
                f"in the last {Config.BRUTE_FORCE_WINDOW}s"
            ),
            parsed_entry = parsed_entry,
        )
    return None


def _check_file_access(parsed_entry, fields):
    filepath = fields.get("filepath", "")

    for sensitive in SENSITIVE_FILES:
        if sensitive in filepath:
            return _make_event(
                event_type  = "sensitive_file_access",
                severity    = "high",
                source_ip   = None,
                username    = None,
                description = f"Sensitive file accessed: {filepath}",
                parsed_entry = parsed_entry,
            )
    return None


def _make_event(event_type, severity, source_ip, username, description, parsed_entry):
    return {
        "event_type":  event_type,
        "severity":    severity,
        "source_ip":   source_ip,
        "username":    username,
        "description": description,
        "timestamp":   parsed_entry["timestamp"],
    }
