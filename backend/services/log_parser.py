import re
from datetime import datetime, timedelta
import time

# ── Regex patterns ──────────────────────────────────────────────────────────

# Standard syslog: Mar  8 10:23:15 hostname process[pid]:
SYSLOG_HEADER = re.compile(
    r'^(?:<\d+>)?'
    r'(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
    r'([\w\-\.]+)\s+'
    r'([\w\-\.\/]+)(?:\[(\d+)\])?:\s+'
    r'(.*)$'
)

# Systemd journal: 2026-03-08T06:04:49.056851+00:00 hostname process[pid]:
SYSLOG_HEADER_ISO = re.compile(
    r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[\.\d]*[\+\-]\d{2}:\d{2})\s+'
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
AUDIT_SADDR     = re.compile(r'saddr=([0-9A-Fa-f]+)')

TZ_OFFSET = re.compile(r'([+-])(\d{2}):(\d{2})$')


def _parse_timestamp(ts_str: str) -> datetime:
    """Parse either ISO 8601 or standard syslog timestamp, converting to UTC."""
    # ISO 8601 with timezone: 2026-03-13T09:46:25.187928+03:00
    try:
        ts_clean = ts_str[:19]
        dt = datetime.strptime(ts_clean, "%Y-%m-%dT%H:%M:%S")
        m = TZ_OFFSET.search(ts_str)
        if m:
            sign   = 1 if m.group(1) == '+' else -1
            offset = timedelta(hours=int(m.group(2)), minutes=int(m.group(3)))
            dt     = dt - (sign * offset)
        return dt
    except ValueError:
        pass

    # Standard syslog: Mar 13 10:10:04 — no timezone, assume local time
    try:
        dt           = datetime.strptime(f"{datetime.utcnow().year} {ts_str}", "%Y %b %d %H:%M:%S")
        local_offset = timedelta(seconds=-time.timezone)
        return dt - local_offset
    except ValueError:
        pass

    return datetime.utcnow()


def decode_saddr(saddr_hex: str) -> dict:
    """
    Decode auditd SOCKADDR hex string into address family, IP, and port.

    Structure:
      IPv4 (AF_INET=2):  0200 <port:2> <ip:4> <padding:8>  — 16 bytes total
      IPv6 (AF_INET6=10): 0A00 <port:2> <flowinfo:4> <ip:16> <scope:4> — 28 bytes
      Unix (AF_UNIX=1):  0100 <path:...>  — skip these
    """
    if not saddr_hex or len(saddr_hex) < 4:
        return {}

    try:
        family = saddr_hex[:4].upper()

        # Unix domain socket — local IPC, not a real network connection
        if family == "0100":
            return {}

        # IPv4
        if family == "0200" and len(saddr_hex) >= 16:
            port = int(saddr_hex[4:8], 16)
            ip   = ".".join(str(int(saddr_hex[i:i+2], 16)) for i in range(8, 16, 2))
            return {"family": "ipv4", "dst_ip": ip, "dst_port": port}

        # IPv6
        if family == "0A00" and len(saddr_hex) >= 56:
            port    = int(saddr_hex[4:8], 16)
            ip_hex  = saddr_hex[16:48]
            groups  = [ip_hex[i:i+4] for i in range(0, 32, 4)]
            ip      = ":".join(groups)
            return {"family": "ipv6", "dst_ip": ip, "dst_port": port}

    except (ValueError, IndexError):
        pass

    return {}


def parse(raw: str) -> dict:
    raw = raw.strip()
    if not raw:
        return None

    ts_str = hostname = process = pid = message = None

    # Try standard syslog format first (live rsyslog)
    match = SYSLOG_HEADER.match(raw)
    if match:
        ts_str, hostname, process, pid, message = match.groups()

    # Try ISO format (historical logs from systemd journal)
    if not match:
        match = SYSLOG_HEADER_ISO.match(raw)
        if match:
            ts_str, hostname, process, pid, message = match.groups()

    if not match:
        return None

    proc = process.lower()

    return {
        "timestamp": _parse_timestamp(ts_str),
        "host":      hostname,
        "process":   proc,
        "pid":       int(pid) if pid else None,
        "message":   message,
        "log_type":  _classify(proc, message),
        "raw":       raw,
        "parsed":    _extract_fields(proc, message),
    }


def _classify(process: str, message: str) -> str:
    if any(p in process for p in ["sshd", "ssh"]):
        return "ssh"
    if "sudo" in process:
        return "sudo"
    if "audisp-syslog" in process or "audisp" in process:
        # Network connect syscall logs also come through audisp-syslog
        if "network_connect" in message or "process_exec" in message:
            return "network"
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

        if atype == "SOCKADDR":
            saddr_match = AUDIT_SADDR.search(message)
            if saddr_match:
                decoded = decode_saddr(saddr_match.group(1))
                fields.update(decoded)
                fields["event"]     = "network_connect"
                fields["saddr_hex"] = saddr_match.group(1)

        elif atype == "PATH":
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