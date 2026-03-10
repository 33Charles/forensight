import re
from datetime import datetime

# ── Regex patterns ──────────────────────────────────────────────────────────

# Standard syslog header:  Mar  8 10:23:15 hostname process[pid]:
SYSLOG_HEADER = re.compile(
    r'^(?:<\d+>)?'                                  # optional priority <34>
    r'(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'        # timestamp
    r'([\w\-\.]+)\s+'                               # hostname
    r'([\w\-\.\/]+)(?:\[(\d+)\])?:\s+'              # process[pid]:
    r'(.*)$'                                        # message
)

# SSH patterns
SSH_FAILED   = re.compile(r'Failed password for (?:invalid user )?(\S+) from ([\d\.]+) port (\d+)')
SSH_ACCEPTED = re.compile(r'Accepted (?:password|publickey) for (\S+) from ([\d\.]+) port (\d+)')
SSH_INVALID  = re.compile(r'Invalid user (\S+) from ([\d\.]+)')
SSH_DISCONNECT = re.compile(r'Disconnected from (?:invalid user )?(\S+)? ?([\d\.]+) port (\d+)')

# Sudo / privilege escalation
SUDO_CMD     = re.compile(r'(\S+)\s*:\s*TTY=(\S+)\s*;\s*PWD=(\S+)\s*;\s*USER=(\S+)\s*;\s*COMMAND=(.*)')
SUDO_FAIL    = re.compile(r'authentication failure.*user=(\S+)')
SUDO_NOT_ALLOWED = re.compile(
    r'(\S+)\s*:.*(?:user NOT in sudoers|is not in the sudoers file)',
    re.IGNORECASE
)

# Auditd file access
AUDIT_SYSCALL = re.compile(r'type=SYSCALL.*comm="([^"]+)".*exe="([^"]+)"')
AUDIT_PATH    = re.compile(r'type=PATH.*name="([^"]+)"')
AUDIT_USER    = re.compile(r'type=USER_AUTH.*acct="([^"]+)".*res=(\w+)')


def parse(raw: str) -> dict:
    """
    Parse a raw syslog line into a structured dict.
    Returns None if the line cannot be parsed.
    """
    raw = raw.strip()
    if not raw:
        return None

    match = SYSLOG_HEADER.match(raw)
    if not match:
        return None

    ts_str, hostname, process, pid, message = match.groups()

    # Parse timestamp — add current year since syslog omits it
    try:
        ts = datetime.strptime(f"{datetime.now().year} {ts_str}", "%Y %b %d %H:%M:%S")
    except ValueError:
        ts = datetime.utcnow()

    entry = {
        "timestamp":   ts,
        "host":        hostname,
        "process":     process.lower(),
        "pid":         int(pid) if pid else None,
        "message":     message,
        "log_type":    _classify(process.lower(), message),
        "raw":         raw,
        "parsed":      _extract_fields(process.lower(), message),
    }
    return entry


def _classify(process: str, message: str) -> str:
    """Classify the log entry into a type."""
    if any(p in process for p in ["sshd", "ssh"]):
        return "ssh"
    if "sudo" in process:
        return "sudo"
    if "audit" in process or message.startswith("type="):
        return "file_access"
    if any(p in process for p in ["login", "pam", "auth"]):
        return "auth"
    return "system"


def _extract_fields(process: str, message: str) -> dict:
    """
    Extract useful fields from the message depending on log type.
    Returns a dict of extracted values (ip, username, command, etc.)
    """
    fields = {}

    # SSH failed login
    m = SSH_FAILED.search(message)
    if m:
        fields["event"]    = "ssh_failed_login"
        fields["username"] = m.group(1)
        fields["src_ip"]   = m.group(2)
        fields["port"]     = m.group(3)
        return fields

    # SSH successful login
    m = SSH_ACCEPTED.search(message)
    if m:
        fields["event"]    = "ssh_accepted_login"
        fields["username"] = m.group(1)
        fields["src_ip"]   = m.group(2)
        fields["port"]     = m.group(3)
        return fields

    # SSH invalid user
    m = SSH_INVALID.search(message)
    if m:
        fields["event"]    = "ssh_invalid_user"
        fields["username"] = m.group(1)
        fields["src_ip"]   = m.group(2)
        return fields

    # Sudo command execution
    m = SUDO_CMD.search(message)
    if m:
        fields["event"]    = "sudo_command"
        fields["username"] = m.group(1)
        fields["run_as"]   = m.group(4)
        fields["command"]  = m.group(5)
        return fields

    # Sudo authentication failure
    m = SUDO_FAIL.search(message)
    if m:
        fields["event"]    = "sudo_auth_failure"
        fields["username"] = m.group(1)
        return fields
    
    if "sudo" in process:
        m = SUDO_FAIL.search(message)
        if m:
            fields["event"]    = "sudo_auth_failure"
            fields["username"] = m.group(1)
            return fields
        
        m = SUDO_NOT_ALLOWED.search(message)
        if m:
            fields["event"]    = "sudo_not_allowed"
            fields["username"] = m.group(1)
            return fields

    # Auditd file access
    m = AUDIT_PATH.search(message)
    if m:
        fields["event"]    = "file_access"
        fields["filepath"] = m.group(1)
        return fields

    return fields
