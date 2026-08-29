import json


def parse_json(raw: str):
    payload = json.loads(raw)
    if isinstance(payload, list):
        return [normalize(item) for item in payload]
    return normalize(payload)


def normalize(event: dict):
    return {
        "timestamp": event.get("timestamp", ""),
        "host": event.get("host", "unknown"),
        "severity": event.get("severity", "INFO"),
        "message": event.get("message", ""),
        "source": event.get("source", "api"),
        "event_type": event.get("event_type", "unknown"),
        "raw": event,
    }
