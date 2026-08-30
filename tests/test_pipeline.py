import json
from pathlib import Path

from app.detector.format_detector import detect_format
from app.enrichment.geoip import enrich_geoip
from app.enrichment.threat_intel import enrich_threat_intel
from app.main import app, process_log_file
from app.ml.anomaly_model import score_event_anomaly
from app.normalizer.normalizer import normalize_event
from app.parser.cef_parser import parse_cef
from app.parser.json_parser import parse_json
from app.parser.key_value_parser import parse_key_value
from app.parser.syslog_parser import parse_syslog
from fastapi.testclient import TestClient


def test_detects_syslog_format():
    path = Path(__file__).resolve().parents[1] / 'sample_logs' / 'linux.log'
    assert detect_format(path.read_text()) == 'syslog'


def test_parses_json_log():
    payload = '{"timestamp":"2026-08-28T10:15:00Z","host":"web-01","severity":"INFO","message":"login success"}'
    result = parse_json(payload)
    assert result['host'] == 'web-01'
    assert result['severity'] == 'INFO'


def test_parses_cef_log():
    payload = 'CEF:0|Palo Alto|PAN-OS|11.0|THREAT|Suspicious Traffic|8|src=10.0.0.12 msg=malware-c2'
    result = parse_cef(payload)
    assert result['device_vendor'] == 'Palo Alto'
    assert result['device_product'] == 'PAN-OS'
    assert result['src_ip'] == '10.0.0.12'


def test_process_log_file_returns_normalized_events():
    path = Path(__file__).resolve().parents[1] / 'sample_logs' / 'sample.json'
    events = process_log_file(str(path))
    assert len(events) == 2
    assert events[0]['event_type'] == 'authentication'
    assert events[1]['source'] == 'api'


def test_parses_syslog_line():
    line = 'Aug  5 12:00:00 web-01 sshd[1234]: Failed password for invalid user root from 192.168.1.10 port 22 ssh2'
    result = parse_syslog(line)
    assert result['host'] == 'web-01'
    assert result['app_name'] == 'sshd'
    assert result['source_ip'] == '192.168.1.10'


def test_detects_key_value_format():
    payload = 'src=10.0.0.5 dst=8.8.8.8 action=deny port=443'
    assert detect_format(payload) == 'key_value'


def test_parses_key_value_log():
    result = parse_key_value('src=10.0.0.5 dst=8.8.8.8 action=deny port=443')
    assert result['src'] == '10.0.0.5'
    assert result['dst'] == '8.8.8.8'
    assert result['port'] == '443'


def test_normalization_builds_canonical_schema():
    result = normalize_event({
        'src': '10.0.0.5',
        'dst': '8.8.8.8',
        'action': 'deny',
        'severity': '5'
    }, source='firewall')
    assert result['network']['source_ip'] == '10.0.0.5'
    assert result['event']['action'] == 'deny'
    assert result['source'] == 'firewall'


def test_api_accepts_log_payload():
    client = TestClient(app)
    response = client.post('/logs', json={'log': 'src=10.0.0.5 dst=8.8.8.8 action=deny'})
    assert response.status_code == 200
    assert response.json()['network']['destination_ip'] == '8.8.8.8'


def test_geoip_enrichment_uses_known_ip_ranges():
    event = {'network': {'source_ip': '8.8.8.8'}}
    result = enrich_geoip(event)
    assert result['enrichment']['country'] == 'US'


def test_threat_intel_enrichment_marks_suspicious_ip():
    event = {'network': {'source_ip': '1.2.3.4'}}
    result = enrich_threat_intel(event)
    assert result['threat']['reputation'] == 'suspicious'


def test_dashboard_endpoint_returns_html():
    client = TestClient(app)
    response = client.get('/dashboard')
    assert response.status_code == 200
    assert 'Universal Log Framework' in response.text
    assert 'Process Log' in response.text


def test_events_endpoint_returns_logged_events():
    client = TestClient(app)
    client.post('/logs', json={'log': 'src=1.2.3.4 dst=8.8.8.8 action=deny'})
    response = client.get('/events')
    assert response.status_code == 200
    payload = response.json()
    assert isinstance(payload, list)
    assert any(item.get('network', {}).get('source_ip') == '1.2.3.4' for item in payload)


def test_health_endpoint_reports_runtime_status():
    client = TestClient(app)
    response = client.get('/health')
    assert response.status_code == 200
    payload = response.json()
    assert payload['status'] == 'ok'
    assert 'total_events' in payload


def test_summary_endpoint_reports_key_security_metrics():
    client = TestClient(app)
    response = client.get('/summary')
    assert response.status_code == 200
    payload = response.json()
    assert payload['total_events'] >= 1
    assert 'high_severity' in payload
    assert 'suspicious_ips' in payload
    assert 'blocked_events' in payload


def test_ml_anomaly_model_scores_suspicious_activity():
    event = {
        'event': {'severity': 'critical', 'action': 'deny'},
        'network': {'source_ip': '1.2.3.4'},
        'threat': {'reputation': 'suspicious'},
        'enrichment': {'country': 'CN'}
    }
    score = score_event_anomaly(event)
    assert 0.5 <= score <= 1.0


def test_ml_insights_endpoint_returns_model_outputs():
    client = TestClient(app)
    response = client.get('/api/ml/insights')
    assert response.status_code == 200
    payload = response.json()
    assert 'anomaly_score' in payload
    assert 'threat_label' in payload


def test_batch_logs_endpoint():
    client = TestClient(app)
    payload = {
        'logs': [
            'src=10.0.0.5 dst=8.8.8.8 action=deny',
            'CEF:0|Palo Alto|PAN-OS|11.0|THREAT|C2-Beacon|8|src=1.2.3.4 msg=malware',
        ]
    }
    response = client.post('/api/logs/batch', json=payload)
    assert response.status_code == 200
    events = response.json()
    assert len(events) == 2
    assert events[0]['network']['destination_ip'] == '8.8.8.8'


def test_clear_events_endpoint():
    client = TestClient(app)
    response = client.post('/api/events/clear')
    assert response.status_code == 200
    payload = response.json()
    assert payload['message'] == 'Event store cleared'
    assert isinstance(payload['count'], int)

