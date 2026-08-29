def validate_event(event: dict) -> bool:
    if not isinstance(event, dict):
        return False
    if event.get("message") or event.get("host") or event.get("timestamp"):
        return True
    if event.get("event", {}).get("action"):
        return True
    if event.get("network"):
        return True
    return False


def validate_events(events):
    return [event for event in events if validate_event(event)]
