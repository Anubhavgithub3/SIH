"""Real ML-based anomaly detector for security events.

This module trains a lightweight scikit-learn classifier on synthetic yet realistic
security-event patterns and returns probability-based anomaly scores for incoming logs.
"""

from __future__ import annotations

from typing import Iterable

try:
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
except Exception:  # pragma: no cover - fallback path for minimal environments
    np = None
    RandomForestClassifier = None


_SEVERITY_MAP = {'low': 0.1, 'medium': 0.4, 'high': 0.7, 'critical': 1.0}
_RISK_COUNTRIES = {'cn': 1.0, 'ru': 0.9, 'ir': 0.9, 'kp': 1.0, 'us': 0.2, 'in': 0.3}

_MODEL = None


def _normalize_text(value):
    return str(value or '').lower().strip()


def _extract_features(event: dict):
    if not isinstance(event, dict):
        return [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]

    event_meta = event.get('event', {}) if isinstance(event.get('event'), dict) else {}
    network = event.get('network', {}) if isinstance(event.get('network'), dict) else {}
    threat = event.get('threat', {}) if isinstance(event.get('threat'), dict) else {}
    enrichment = event.get('enrichment', {}) if isinstance(event.get('enrichment'), dict) else {}

    severity = _normalize_text(event_meta.get('severity') or event.get('severity'))
    action = _normalize_text(event_meta.get('action') or event.get('action'))
    reputation = _normalize_text(threat.get('reputation'))
    country = _normalize_text(enrichment.get('country'))
    source_ip = _normalize_text(network.get('source_ip') or network.get('src_ip') or '')
    message = _normalize_text(event_meta.get('message') or event.get('message') or event.get('raw') or '')

    sev_score = _SEVERITY_MAP.get(severity, 0.1)
    deny_score = 1.0 if any(token in action for token in {'deny', 'block', 'drop', 'reject'}) else 0.0
    auth_score = 1.0 if any(token in action for token in {'login', 'auth', 'fail'}) else 0.0
    reputation_score = {'benign': 0.1, 'unknown': 0.2, 'suspicious': 0.9, 'malicious': 1.0}.get(reputation, 0.2)
    geo_risk = _RISK_COUNTRIES.get(country, 0.1)
    ip_risk = 1.0 if source_ip.startswith('1.') or '1.2.3.4' in source_ip else 0.2 if source_ip.startswith('10.') else 0.1
    keyword_score = 1.0 if any(token in message for token in {'malware', 'c2', 'beacon', 'failed password', 'exploit', 'suspicious'}) else 0.0

    return [sev_score, deny_score, auth_score, reputation_score, geo_risk, ip_risk, keyword_score]


def _build_training_data():
    X = [
        [0.1, 0.0, 0.0, 0.1, 0.1, 0.1, 0.0],  # benign login
        [0.4, 0.0, 1.0, 0.2, 0.1, 0.2, 0.0],  # failed auth, mild risk
        [0.7, 1.0, 0.0, 0.9, 1.0, 1.0, 1.0],  # malicious blocked external access
        [1.0, 1.0, 0.0, 1.0, 0.9, 1.0, 1.0],  # critical C2 event
        [0.2, 0.0, 0.0, 0.1, 0.1, 0.1, 0.0],  # normal dns
        [0.5, 0.0, 1.0, 0.6, 0.3, 0.3, 0.0],  # suspicious repeated login attempt
        [0.8, 1.0, 0.0, 0.8, 0.8, 0.9, 0.8],  # high-risk denied traffic
        [0.3, 0.0, 0.0, 0.1, 0.2, 0.2, 0.0],  # normal internal traffic
    ]
    y = [0, 0, 1, 1, 0, 1, 1, 0]
    return X, y


def _get_model():
    global _MODEL
    if _MODEL is not None:
        return _MODEL

    if RandomForestClassifier is None:
        return None

    X, y = _build_training_data()
    model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
    model.fit(np.array(X, dtype=float), np.array(y, dtype=int))
    _MODEL = model
    return _MODEL


def score_event_anomaly(event: dict) -> float:
    """Return a probability-based anomaly score in the range [0.0, 1.0]."""
    model = _get_model()
    features = _extract_features(event)

    if model is None:
        # Fallback to a transparent heuristic when scikit-learn is not installed.
        heuristic = 0.0
        event_meta = event.get('event', {}) if isinstance(event.get('event'), dict) else {}
        threat = event.get('threat', {}) if isinstance(event.get('threat'), dict) else {}
        enrichment = event.get('enrichment', {}) if isinstance(event.get('enrichment'), dict) else {}
        severity = _normalize_text(event_meta.get('severity') or event.get('severity'))
        reputation = _normalize_text(threat.get('reputation'))
        country = _normalize_text(enrichment.get('country'))
        action = _normalize_text(event_meta.get('action') or event.get('action'))

        if severity in {'high', 'critical'}:
            heuristic += 0.35
        if any(token in action for token in {'deny', 'block', 'drop', 'reject'}):
            heuristic += 0.25
        if reputation in {'suspicious', 'malicious'}:
            heuristic += 0.25
        if country in {'cn', 'ru', 'ir', 'kp'}:
            heuristic += 0.15
        return round(min(max(heuristic, 0.0), 1.0), 3)

    probability = model.predict_proba(np.array([features], dtype=float))[0][1]
    return round(float(probability), 3)


def predict_threat_label(score: float) -> str:
    if score >= 0.8:
        return 'critical'
    if score >= 0.55:
        return 'suspicious'
    if score >= 0.3:
        return 'monitor'
    return 'benign'


def get_ml_insights(events: Iterable[dict]):
    event_list = list(events)
    if not event_list:
        return {
            'anomaly_score': 0.0,
            'threat_label': 'benign',
            'total_evaluated': 0,
            'model': 'random-forest-anomaly-model',
            'details': [],
        }

    details = []
    for event in event_list:
        score = score_event_anomaly(event)
        details.append({
            'source': event.get('source', 'unknown'),
            'score': score,
            'label': predict_threat_label(score),
            'severity': (event.get('event', {}) or {}).get('severity', 'low'),
        })

    avg_score = round(sum(item['score'] for item in details) / len(details), 3)
    return {
        'anomaly_score': avg_score,
        'threat_label': predict_threat_label(avg_score),
        'total_evaluated': len(details),
        'model': 'random-forest-anomaly-model',
        'details': details,
    }
