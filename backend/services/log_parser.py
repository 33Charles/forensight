import re
from datetime import datetime

# ── Regex patterns ──────────────────────────────────────────────────────────

SYSLOG_HEADER = re.compile(
    r'^(?:<\d+>)?'
    r'(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
    r'([\w\-\.]+)\s+'
    r'([\w\-\.\/]+)(?:\[(\d+)\])?:\s+'
    r'(.*)$'
)

# SSH patterns
SSH_FAILED       = re.compile(r'Failed password for (?:invalid user )?(\S+) from ([\d\.]+) port (\d+)')
SSH_ACCEPTED     = re.compile(r'Accepted (?:password|publickey) for (\S+) from ([\d\.]+) port (\d+)')
SSH_INVALID      = re.compile(r'Invalid user (\S+) from ([\d\.]+)')
SSH_DISCONNECT   = re.compile(r'Disconnected from (?:invalid user )?(\S+)? ?([\d\.]+) port (\d+)')

# Sudo / privilege escalation
SUDO_CMD         = re.compile(r'(\S+)\s*:\s*TTY=(\S+)\s*;\s*PWD=(\S+)\s*;\s*USER=(\S+)\s*;\s*COMMAND=(.*)')
SUDO_FAIL        = re.compile(r'authentication failure.*user=(\S+)')
SUDO_NOT_ALLOWED = re.compile(
    r'(\S+)\s*:.*(?:user NOT in sudoers|is not in the sudoers file)',
    re.IGNORECASE
)

# Auditd patterns
AUDIT_EVENT_ID  = re.compile(r'msg=audit\([\d\.]+:(\d+)\)')
AUDIT_TYPE      = re.compile(r'type=(\w+)')
AUDIT_KEY       = re.compile(r'key="([^"]+)"')
AUDIT_PATH_NAME = re.compile(r'name="([^"]+)"')
AUDIT_COMM      = re.compile(r'comm="([^"]+)"')
AUDIT_UID       = re.compile(r'\buid=(\d+)')
AUDIT_AUID      = re.compile(r'AUID="([^"]+)"')
AUDIT_EXE       = re.compile(r'exe="([^"]+)"')
AUDIT_SUCCESS   = re.compile(r'success=(\w+)')


def parse(raw: str) -> dict:
    raw = raw.strip()
    if not raw:
        return None

    match = SYSLOG_HEADER.match(raw)
    if not match:
        return None

    ts_str, hostname, process, pid, message = match.groups()

    try:
        ts = datetime.strptime(f"{datetime.now().year} {ts_str}", "%Y %b %d %H:%M:%S")
    except ValueError:
        ts = datetime.utcnow()

    return {
        "timestamp": ts,
        "host":      hostname,
        "process":   process.lower(),
        "pid":       int(pid) if pid else None,
        "message":   message,
        "log_type":  _classify(process.lower(), message),
        "raw":       raw,
        "parsed":    _extract_fields(process.lower(), message),
    }


def _classify(process: str, message: str) -> str:
    if any(p in process for p in ["sshd", "ssh"]):
        return "ssh"
    if "sudo" in process:
        return "sudo"
    if "audisp-syslog" in process or "audisp" in process:
        return "file_access"
    if "audit" in process or message.startswith("type="):
        return "file_access"
    if any(p in process for p in ["login", "pam", "auth"]):
        return "auth"
    return "system"


def _extract_fields(process: str, message: str) -> dict:
    fields = {}

    # ── SSH ───────────────────────────────────────────────────────────────
    m = SSH_FAILED.search(message)
    if m:
        fields["event"]    = "ssh_failed_login"
        fields["username"] = m.group(1)
        fields["src_ip"]   = m.group(2)
        fields["port"]     = m.group(3)
        return fields

    m = SSH_ACCEPTED.search(message)
    if m:
        fields["event"]    = "ssh_accepted_login"
        fields["username"] = m.group(1)
        fields["src_ip"]   = m.group(2)
        fields["port"]     = m.group(3)
        return fields

    m = SSH_INVALID.search(message)
    if m:
        fields["event"]    = "ssh_invalid_user"
        fields["username"] = m.group(1)
        fields["src_ip"]   = m.group(2)
        return fields

    # ── Sudo ──────────────────────────────────────────────────────────────
    m = SUDO_CMD.search(message)
    if m:
        fields["event"]    = "sudo_command"
        fields["username"] = m.group(1)
        fields["run_as"]   = m.group(4)
        fields["command"]  = m.group(5)
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

    # ── Auditd ────────────────────────────────────────────────────────────
    if "audisp-syslog" in process or "audisp" in process:
        audit_type = AUDIT_TYPE.search(message)
        if not audit_type:
            return fields

        atype    = audit_type.group(1)
        event_id = AUDIT_EVENT_ID.search(message)

        fields["audit_type"] = atype
        fields["event_id"]   = event_id.group(1) if event_id else None

        if atype == "PATH":
            m = AUDIT_PATH_NAME.search(message)
            if m:
                fields["event"]     = "file_access"
                fields["filepath"]  = m.group(1)
                k = AUDIT_KEY.search(message)
                fields["audit_key"] = k.group(1) if k else None

        elif atype == "SYSCALL":
            comm = AUDIT_COMM.search(message)
            exe  = AUDIT_EXE.search(message)
            auid = AUDIT_AUID.search(message)
            key  = AUDIT_KEY.search(message)
            fields["command"]   = comm.group(1) if comm else None
            fields["exe"]       = exe.group(1) if exe else None
            fields["auid"]      = auid.group(1) if auid else None
            fields["audit_key"] = key.group(1) if key else None

        elif atype in ["USER_AUTH", "USER_ACCT"]:
            auid = AUDIT_AUID.search(message)
            fields["auid"] = auid.group(1) if auid else None

        return fields

    return fields