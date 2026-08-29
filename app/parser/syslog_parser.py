import re


SYSLOG_RE = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<app>[^\[]+)\[(?P<pid>\d+)\]:\s*(?P<message>.*)$'
)


def parse_syslog(line: str):
    match = SYSLOG_RE.match(line.strip())
    if not match:
        return {
            "timestamp": "",
            "host": "unknown",
            "app_name": "unknown",
            "severity": "INFO",
            "message": line.strip(),
            "source_ip": "",
        }

    msg = match.group('message')
    source_ip = ""
    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', msg)
    if ip_match:
        source_ip = ip_match.group(0)

    return {
        "timestamp": f"{match.group('month')} {match.group('day')} {match.group('time')}",
        "host": match.group('host'),
        "app_name": match.group('app').strip(),
        "severity": "INFO",
        "message": msg,
        "source_ip": source_ip,
    }
