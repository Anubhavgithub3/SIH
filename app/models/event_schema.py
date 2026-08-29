from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass
class Event:
    source: str = "unknown"
    timestamp: str = ""
    host: str = ""
    severity: str = "INFO"
    event_type: str = "unknown"
    message: str = ""
    raw: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        payload = {
            "source": self.source,
            "timestamp": self.timestamp,
            "host": self.host,
            "severity": self.severity,
            "event_type": self.event_type,
            "message": self.message,
            "raw": self.raw,
        }
        payload.update(self.metadata)
        return payload
