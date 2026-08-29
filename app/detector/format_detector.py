import json
import re


def detect_format(content: str) -> str:
    text = content.strip()
    if not text:
        return "unknown"
    if text.startswith("{") or text.startswith("["):
        try:
            json.loads(text)
            return "json"
        except json.JSONDecodeError:
            pass
    if text.startswith("CEF:"):
        return "cef"
    if text.startswith("LEEF:"):
        return "leef"
    if re.search(r"^\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+", text, re.MULTILINE):
        return "syslog"
    if re.search(r'\b[A-Za-z_]+\s*=\s*[^\s]+', text):
        return "key_value"
    if "|" in text and "src=" in text:
        return "cef"
    return "unknown"
