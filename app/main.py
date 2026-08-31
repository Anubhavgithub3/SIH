import json
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.collector.audit_vault import (
    audit_and_backup_raw_log,
    quarantine_payload,
    get_audit_logs,
    get_quarantine_items,
    process_quarantine_action
)
from app.collector.file_collector import read_log_file
from app.detector.format_detector import detect_format
from app.enrichment.geoip import enrich_geoip
from app.enrichment.threat_intel import enrich_threat_intel
from app.ml.anomaly_model import get_ml_insights
from app.normalizer.normalizer import normalize_event
from app.parser.cef_parser import parse_cef
from app.parser.json_parser import parse_json
from app.parser.key_value_parser import parse_key_value
from app.parser.syslog_parser import parse_syslog
from app.validator.validator import validate_events

app = FastAPI(title='Universal Log Framework')

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

START_TIME = time.time()

FRONTEND_DIST_DIR = Path(__file__).resolve().parents[1] / 'frontend' / 'dist'
if (FRONTEND_DIST_DIR / 'assets').exists():
    app.mount('/assets', StaticFiles(directory=str(FRONTEND_DIST_DIR / 'assets')), name='react-assets')

EVENT_STORE = [
    {
        'timestamp': '2026-08-30T10:32:00Z',
        'source': 'firewall',
        'event': {'action': 'blocked', 'type': 'firewall_event', 'severity': 'high'},
        'network': {'source_ip': '192.168.1.10', 'destination_ip': '8.8.8.8'},
        'enrichment': {'country': 'IN'},
        'threat': {'reputation': 'unknown'},
    },
    {
        'timestamp': '2026-08-30T10:31:00Z',
        'source': 'linux',
        'event': {'action': 'login', 'type': 'authentication', 'severity': 'medium'},
        'network': {'source_ip': '10.0.0.5', 'destination_ip': '10.0.0.8'},
        'enrichment': {'country': 'US'},
        'threat': {'reputation': 'benign'},
    },
    {
        'timestamp': '2026-08-30T10:30:00Z',
        'source': 'api',
        'event': {'action': 'alert', 'type': 'threat', 'severity': 'critical'},
        'network': {'source_ip': '1.2.3.4', 'destination_ip': '10.5.2.4'},
        'enrichment': {'country': 'CN'},
        'threat': {'reputation': 'suspicious'},
    },
]


def _get_event_severity(event: dict) -> str:
    if not isinstance(event, dict):
        return 'low'
    severity = event.get('severity') or event.get('event', {}).get('severity') or 'low'
    return str(severity).lower()


def _get_event_action(event: dict) -> str:
    if not isinstance(event, dict):
        return ''
    event_meta = event.get('event', {}) if isinstance(event.get('event'), dict) else {}
    action = event_meta.get('action') or event.get('action') or ''
    return str(action).lower()


def _get_sources(events):
    return sorted({str(event.get('source') or 'unknown') for event in events if isinstance(event, dict)})


def _build_summary(events=None):
    events = list(EVENT_STORE if events is None else events)
    total_events = len(events)
    high_severity = sum(1 for event in events if _get_event_severity(event) in {'high', 'critical'})
    blocked_events = sum(1 for event in events if 'deny' in _get_event_action(event) or 'block' in _get_event_action(event))

    suspicious_ips = []
    for event in events:
        network = event.get('network', {}) if isinstance(event.get('network'), dict) else {}
        source_ip = network.get('source_ip') or network.get('src_ip')
        threat = event.get('threat', {}) if isinstance(event.get('threat'), dict) else {}
        reputation = str(threat.get('reputation') or 'unknown').lower()
        if source_ip and reputation in {'suspicious', 'malicious'}:
            suspicious_ips.append(source_ip)

    ml_summary = get_ml_insights(events)
    return {
        'total_events': total_events,
        'high_severity': high_severity,
        'blocked_events': blocked_events,
        'suspicious_ips': suspicious_ips,
        'sources': _get_sources(events),
        'ml_anomaly_score': ml_summary['anomaly_score'],
        'ml_threat_label': ml_summary['threat_label'],
        'last_updated': datetime.now(timezone.utc).isoformat(),
    }


def _build_dynamic_alerts(events):
    alerts = []
    seen = set()
    for e in reversed(events):
        if not isinstance(e, dict):
            continue
        threat = e.get('threat', {}) if isinstance(e.get('threat'), dict) else {}
        event_meta = e.get('event', {}) if isinstance(e.get('event'), dict) else {}
        network = e.get('network', {}) if isinstance(e.get('network'), dict) else {}
        enrichment = e.get('enrichment', {}) if isinstance(e.get('enrichment'), dict) else {}

        rep = str(threat.get('reputation') or '').lower()
        sev = str(event_meta.get('severity') or e.get('severity') or 'low').lower()
        src_ip = network.get('source_ip') or network.get('src_ip') or 'Unknown'
        msg = event_meta.get('message') or e.get('message') or 'Security Event Flagged'
        country = enrichment.get('country') or 'GLOBAL'

        if rep in {'suspicious', 'malicious'} or sev in {'critical', 'high'}:
            key = f"{src_ip}:{msg}"
            if key not in seen:
                seen.add(key)
                alerts.append({
                    'title': f"{event_meta.get('action', 'Security Event').upper()}: {msg}",
                    'severity': sev,
                    'source': src_ip if src_ip != 'Unknown' else country,
                    'summary': f"Normalized telemetric hit from {country} ({src_ip}). {msg}"
                })
        if len(alerts) >= 10:
            break

    if not alerts:
        alerts = [
            {'title': 'System Status Normal', 'severity': 'low', 'source': 'Core', 'summary': 'Telemetry stream operational. Zero critical threats detected.'}
        ]
    return alerts


def _build_dynamic_incidents(events):
    incidents = []
    seen = set()
    for e in reversed(events):
        if not isinstance(e, dict):
            continue
        event_meta = e.get('event', {}) if isinstance(e.get('event'), dict) else {}
        threat = e.get('threat', {}) if isinstance(e.get('threat'), dict) else {}
        ml = e.get('ml_prediction', {}) if isinstance(e.get('ml_prediction'), dict) else {}

        sev = str(event_meta.get('severity') or e.get('severity') or 'low').lower()
        msg = event_meta.get('message') or 'Anomaly Activity'
        score = ml.get('score') if isinstance(ml, dict) and 'score' in ml else (0.92 if sev == 'critical' else 0.75 if sev == 'high' else 0.45)

        if sev in {'critical', 'high', 'medium'} or threat.get('reputation') in {'suspicious', 'malicious'}:
            key = msg
            if key not in seen:
                seen.add(key)
                score_val = int(score * 100) if isinstance(score, (int, float)) and score <= 1.0 else int(score) if isinstance(score, (int, float)) else 50
                incidents.append({
                    'title': msg,
                    'severity': sev,
                    'score': score_val
                })
        if len(incidents) >= 10:
            break

    if not incidents:
        incidents = [{'title': 'Baseline Monitoring Active', 'severity': 'low', 'score': 15}]
    return incidents


def _build_dynamic_assets(events):
    assets_map = {}
    for e in events:
        if not isinstance(e, dict):
            continue
        host = e.get('host', {}) if isinstance(e.get('host'), dict) else {}
        net = e.get('network', {}) if isinstance(e.get('network'), dict) else {}
        sev = _get_event_severity(e)

        asset_name = host.get('name') or net.get('destination_ip') or net.get('dst_ip') or 'api-gateway'
        if asset_name not in assets_map:
            assets_map[asset_name] = {'name': asset_name, 'status': 'healthy', 'risk': 'low', 'owner': 'Security'}

        if sev in {'critical', 'high'}:
            assets_map[asset_name]['status'] = 'critical'
            assets_map[asset_name]['risk'] = 'high'
        elif sev == 'medium' and assets_map[asset_name]['status'] != 'critical':
            assets_map[asset_name]['status'] = 'watch'
            assets_map[asset_name]['risk'] = 'medium'

    assets_list = list(assets_map.values())
    if not assets_list:
        assets_list = [
            {'name': 'web-01', 'status': 'healthy', 'risk': 'low', 'owner': 'Platform'},
            {'name': 'api-gateway', 'status': 'watch', 'risk': 'medium', 'owner': 'Security'},
            {'name': 'db-prod-02', 'status': 'critical', 'risk': 'high', 'owner': 'Data'},
        ]
    return assets_list[:8]


def _build_overview():
    summary = _build_summary(EVENT_STORE)
    alerts = _build_dynamic_alerts(EVENT_STORE)
    incidents = _build_dynamic_incidents(EVENT_STORE)
    assets = _build_dynamic_assets(EVENT_STORE)
    return {
        'summary': summary,
        'alerts': alerts,
        'incidents': incidents,
        'assets': assets,
        'events': EVENT_STORE[-50:] if len(EVENT_STORE) > 50 else EVENT_STORE,
        'generated_at': datetime.now(timezone.utc).isoformat(),
    }


def _parse_raw(raw_text: str):
    fmt = detect_format(raw_text)
    if fmt == 'json':
        parsed = parse_json(raw_text)
        if isinstance(parsed, list):
            return parsed
        return [parsed]
    if fmt == 'cef':
        return [parse_cef(raw_text)]
    if fmt == 'leef':
        from app.parser.leef_parser import parse_leef
        return [parse_leef(raw_text)]
    if fmt == 'key_value':
        return [parse_key_value(raw_text)]
    if fmt == 'syslog':
        events = []
        for line in raw_text.splitlines():
            if line.strip():
                events.append(parse_syslog(line))
        return events
    return [{"message": raw_text, "raw": raw_text, "source": "unknown", "event_type": "unknown"}]


def process_log_payload(raw_text: str):
    # 1. SHA-256 Hash & Immutable Audit Backup
    audit_info = audit_and_backup_raw_log(raw_text, source='api')

    # 2. Format Detection & Parsing
    fmt = detect_format(raw_text)
    parsed_events = _parse_raw(raw_text)

    # 3. Threat Quarantine Engine (Unrecognized taxonomy or exploit payloads)
    is_unknown_fmt = fmt == 'unknown'
    has_exploit_sig = any(
        kw in raw_text.lower() for kw in ['<script', 'select *', 'union select', 'drop table', 'chmod 777', 'eval(', '../../etc/passwd']
    )

    quarantine_info = None
    if is_unknown_fmt or has_exploit_sig:
        reason = 'UNRECOGNIZED_LOG_TAXONOMY' if is_unknown_fmt else 'MALICIOUS_EXPLOIT_PAYLOAD'
        quarantine_info = quarantine_payload(raw_text, reason=reason, risk_score=0.95 if has_exploit_sig else 0.85, source='api')

    normalized = []
    for event in parsed_events:
        normal = normalize_event(event, source='api')
        normal = enrich_geoip(normal)
        normal = enrich_threat_intel(normal)

        # Attach Audit & Quarantine Metadata
        normal['audit'] = audit_info
        if quarantine_info:
            normal['quarantine'] = quarantine_info
            if 'event' in normal and isinstance(normal['event'], dict):
                normal['event']['severity'] = 'critical'
                normal['event']['action'] = 'quarantined'
            if 'threat' in normal and isinstance(normal['threat'], dict):
                normal['threat']['reputation'] = 'malicious'
                normal['threat']['score'] = 0.95

        normalized.append(normal)

    valid = validate_events(normalized)
    result = valid[0] if valid else {
        'event': {'type': 'unknown', 'action': 'quarantined' if quarantine_info else 'unparsed', 'severity': 'critical'},
        'metadata': {'processing_status': 'unparsed'},
        'raw_log': raw_text,
        'audit': audit_info
    }
    if quarantine_info and 'quarantine' not in result:
        result['quarantine'] = quarantine_info

    EVENT_STORE.append(result)
    return result


def process_log_file(file_path: str):
    raw_text = read_log_file(file_path)
    file_name = Path(file_path).name
    audit_info = audit_and_backup_raw_log(raw_text, source=f"file:{file_name}")

    fmt = detect_format(raw_text)
    is_unknown_fmt = fmt == 'unknown'
    has_exploit_sig = any(
        kw in raw_text.lower() for kw in ['<script', 'select *', 'union select', 'drop table', 'chmod 777', 'eval(', '../../etc/passwd']
    )

    quarantine_info = None
    if is_unknown_fmt or has_exploit_sig:
        reason = 'UNRECOGNIZED_LOG_TAXONOMY' if is_unknown_fmt else 'MALICIOUS_EXPLOIT_PAYLOAD'
        quarantine_info = quarantine_payload(raw_text, reason=reason, risk_score=0.95 if has_exploit_sig else 0.85, source='file')

    parsed_events = _parse_raw(raw_text)
    normalized = []
    for event in parsed_events:
        normal = normalize_event(event, source='file')
        normal = enrich_geoip(normal)
        normal = enrich_threat_intel(normal)
        normal['audit'] = audit_info
        if quarantine_info:
            normal['quarantine'] = quarantine_info
        if normal.get('event', {}).get('message') or normal.get('metadata'):
            normalized.append(normal)

    valid = validate_events(normalized)
    for v in valid:
        v['audit'] = audit_info
        if quarantine_info and 'quarantine' not in v:
            v['quarantine'] = quarantine_info
    return valid


@app.get('/')
def root():
    if (FRONTEND_DIST_DIR / 'index.html').exists():
        return FileResponse(str(FRONTEND_DIST_DIR / 'index.html'))
    html = """
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Universal Log Framework</title>
        <style>
          :root {
            --bg: #f4f8ff;
            --bg-alt: #edf3ff;
            --panel: rgba(255,255,255,0.8);
            --panel-strong: #ffffff;
            --line: rgba(143,171,216,0.28);
            --text: #12233f;
            --muted: #5e7292;
            --primary: #2d6df6;
            --primary-soft: #edf4ff;
            --deep: #0d1d39;
            --green: #18b77f;
            --green-soft: #ebfff5;
            --amber: #f3b94d;
            --amber-soft: #fff4d9;
            --red: #ea5a77;
            --red-soft: #ffeef3;
            --shadow: 0 20px 52px rgba(17, 32, 64, 0.12);
          }

          * { box-sizing: border-box; }
          html { scroll-behavior: smooth; }
          body {
            margin: 0;
            font-family: Inter, 'Segoe UI', sans-serif;
            background: linear-gradient(180deg, var(--bg) 0%, var(--bg-alt) 100%);
            color: var(--text);
          }

          a { color: inherit; text-decoration: none; }
          img { display: block; max-width: 100%; }

          .container { width: min(1180px, calc(100% - 32px)); margin: 0 auto; }

          .loading-screen {
            position: fixed;
            inset: 0;
            z-index: 50;
            background: linear-gradient(135deg, #f7faff 0%, #eaf2ff 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            transition: opacity 0.6s ease, visibility 0.6s ease;
          }

          .loading-screen.hidden {
            opacity: 0;
            visibility: hidden;
            pointer-events: none;
          }

          .loader-box {
            width: min(420px, 80vw);
            text-align: center;
          }

          .loader-brand {
            display: inline-flex;
            align-items: center;
            gap: 12px;
            font-weight: 800;
            font-size: 0.85rem;
            letter-spacing: 0.12em;
            text-transform: uppercase;
            color: var(--primary);
          }

          .loader-dot {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: linear-gradient(135deg, var(--primary), #86b7ff);
            box-shadow: 0 0 18px rgba(45,109,246,0.5);
            animation: pulse 1.8s infinite;
          }

          .loader-title {
            margin: 20px 0 12px;
            font-size: clamp(2rem, 3vw, 3rem);
            letter-spacing: -0.06em;
          }

          .loader-bar {
            width: 100%;
            height: 10px;
            border-radius: 999px;
            background: rgba(45,109,246,0.1);
            overflow: hidden;
            margin-top: 14px;
          }

          .loader-fill {
            width: 0%;
            height: 100%;
            border-radius: inherit;
            background: linear-gradient(90deg, var(--primary), #76a4ff);
            animation: loading 2.4s ease-in-out forwards;
          }

          .topbar {
            position: sticky;
            top: 0;
            z-index: 20;
            background: rgba(255,255,255,0.75);
            backdrop-filter: blur(14px);
            border-bottom: 1px solid rgba(143,171,216,0.2);
          }

          .nav {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 18px;
            padding: 18px 0;
          }

          .brand {
            display: flex;
            align-items: center;
            gap: 12px;
            font-weight: 800;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            color: var(--primary);
          }
          .brand-mark {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: linear-gradient(135deg, var(--primary), #6dd6ff);
            box-shadow: 0 0 18px rgba(45,109,246,0.5);
          }

          .nav-links {
            display: flex;
            align-items: center;
            gap: 24px;
            color: var(--muted);
            font-size: 0.78rem;
            font-weight: 700;
            letter-spacing: 0.08em;
            text-transform: uppercase;
          }
          .nav-links a { transition: color 0.2s ease; }
          .nav-links a:hover { color: var(--primary); }

          .nav-actions {
            display: flex;
            align-items: center;
            gap: 12px;
          }

          .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 13px 20px;
            border-radius: 12px;
            font-weight: 700;
            border: 1px solid transparent;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
          }
          .btn:hover { transform: translateY(-2px); }
          .btn-primary {
            background: linear-gradient(135deg, var(--primary), #6d8dff);
            color: white;
            box-shadow: 0 18px 30px rgba(45,109,246,0.22);
          }
          .btn-secondary {
            background: rgba(255,255,255,0.7);
            border-color: var(--line);
            color: var(--text);
          }

          .hero {
            padding: 70px 0 40px;
          }

          .hero-grid {
            display: grid;
            grid-template-columns: 1.04fr 0.96fr;
            gap: 28px;
            align-items: center;
          }

          .eyebrow {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: var(--primary-soft);
            color: var(--primary);
            border-radius: 999px;
            padding: 8px 12px;
            font-size: 11px;
            font-weight: 800;
            letter-spacing: 0.12em;
            text-transform: uppercase;
          }

          h1 {
            margin: 18px 0 18px;
            font-size: clamp(2.8rem, 5vw, 5.2rem);
            line-height: 0.98;
            letter-spacing: -0.065em;
          }

          .lead {
            max-width: 60ch;
            color: var(--muted);
            font-size: 1.08rem;
            line-height: 1.8;
          }

          .cta-row {
            display: flex;
            flex-wrap: wrap;
            gap: 14px;
            margin-top: 26px;
          }

          .mini-stats {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 16px;
            margin-top: 34px;
          }

          .stat-box {
            background: rgba(255,255,255,0.72);
            border: 1px solid var(--line);
            border-radius: 18px;
            padding: 18px 16px;
            box-shadow: var(--shadow);
          }
          .stat-label {
            font-size: 11px;
            letter-spacing: 0.1em;
            text-transform: uppercase;
            color: var(--muted);
          }
          .stat-value {
            margin-top: 10px;
            font-size: 2rem;
            font-weight: 800;
            letter-spacing: -0.05em;
          }

          .hero-visual {
            background: linear-gradient(180deg, rgba(255,255,255,0.94), rgba(245,249,255,0.9));
            border: 1px solid var(--line);
            border-radius: 28px;
            padding: 22px;
            box-shadow: var(--shadow);
          }

          .visual-top {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 18px;
          }
          .visual-pill {
            background: var(--green-soft);
            color: var(--green);
            border-radius: 999px;
            padding: 7px 10px;
            font-size: 10px;
            letter-spacing: 0.1em;
            text-transform: uppercase;
            font-weight: 800;
          }

          .metric-grid {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 12px;
            margin-bottom: 18px;
          }
          .mini-card {
            background: var(--primary-soft);
            border: 1px solid rgba(45,109,246,0.08);
            border-radius: 18px;
            padding: 14px 12px;
          }
          .mini-card .label {
            color: var(--muted);
            font-size: 10px;
            text-transform: uppercase;
            letter-spacing: 0.1em;
          }
          .mini-card .value {
            margin-top: 8px;
            font-size: 1.8rem;
            font-weight: 800;
            letter-spacing: -0.05em;
          }

          .event-board {
            background: #f7f9ff;
            border: 1px solid var(--line);
            border-radius: 18px;
            padding: 14px;
          }
          .event-row {
            display: grid;
            grid-template-columns: 1.4fr 1fr 0.85fr;
            gap: 12px;
            padding: 10px 0;
            border-bottom: 1px solid var(--line);
            font-size: 13px;
          }
          .event-row:last-child { border-bottom: none; }
          .tag {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            min-width: 70px;
            padding: 6px 9px;
            border-radius: 999px;
            font-size: 10px;
            font-weight: 800;
            letter-spacing: 0.08em;
            text-transform: uppercase;
          }
          .tag.red { background: var(--red-soft); color: var(--red); }
          .tag.amber { background: var(--amber-soft); color: #9e7300; }
          .tag.green { background: var(--green-soft); color: var(--green); }

          section { padding-top: 88px; }
          .section-title {
            text-align: center;
            margin-bottom: 32px;
          }
          .section-title h2 {
            margin: 0;
            font-size: clamp(2.1rem, 3vw, 3rem);
            letter-spacing: -0.05em;
          }
          .section-title p {
            margin: 14px auto 0;
            max-width: 720px;
            color: var(--muted);
            line-height: 1.8;
          }

          .feature-grid, .usecase-grid, .metrics-grid {
            display: grid;
            grid-template-columns: repeat(3, minmax(220px, 1fr));
            gap: 22px;
          }

          .feature-card, .usecase-card, .metric-card, .process-card {
            background: rgba(255,255,255,0.8);
            border: 1px solid var(--line);
            border-radius: 22px;
            padding: 24px 20px;
            box-shadow: var(--shadow);
          }
          .feature-icon {
            width: 54px;
            height: 54px;
            border-radius: 16px;
            display: flex;
            align-items: center;
            justify-content: center;
            background: linear-gradient(135deg, var(--primary-soft), #dfeeff);
            color: var(--primary);
            font-weight: 800;
            margin-bottom: 18px;
          }
          .feature-card h3, .usecase-card h3, .metric-card h3, .process-card h3 {
            margin: 0 0 12px;
            font-size: 1.25rem;
          }
          .feature-card p, .usecase-card p, .metric-card p, .process-card p {
            margin: 0;
            color: var(--muted);
            line-height: 1.8;
          }

          .architecture-flow {
            display: grid;
            grid-template-columns: repeat(7, minmax(120px, 1fr));
            gap: 14px;
            margin-top: 28px;
          }
          .step-badge {
            width: 36px;
            height: 36px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            border-radius: 50%;
            background: var(--primary-soft);
            color: var(--primary);
            font-weight: 800;
            margin-bottom: 14px;
          }

          .split {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 22px;
            align-items: center;
            margin-top: 30px;
          }
          .half-card {
            background: rgba(255,255,255,0.8);
            border: 1px solid var(--line);
            border-radius: 26px;
            box-shadow: var(--shadow);
            padding: 28px;
          }
          .bullet-list {
            list-style: none;
            padding: 0;
            margin: 18px 0 0;
            display: grid;
            gap: 12px;
          }
          .bullet-list li {
            display: flex;
            align-items: flex-start;
            gap: 12px;
            color: var(--muted);
            line-height: 1.75;
          }
          .bullet-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: linear-gradient(135deg, var(--primary), var(--cyan));
            margin-top: 9px;
            box-shadow: 0 0 12px rgba(45,109,246,0.4);
          }

          .timeline {
            display: grid;
            gap: 18px;
            margin-top: 28px;
          }
          .timeline-item {
            display: grid;
            grid-template-columns: 64px 1fr;
            gap: 18px;
            padding: 16px 18px;
            background: rgba(255,255,255,0.78);
            border: 1px solid var(--line);
            border-radius: 18px;
            box-shadow: var(--shadow);
          }
          .timeline-number {
            width: 52px;
            height: 52px;
            border-radius: 50%;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            background: var(--primary-soft);
            color: var(--primary);
            font-weight: 800;
          }
          .timeline-item h3 { margin: 0 0 6px; }
          .timeline-item p { margin: 0; color: var(--muted); line-height: 1.7; }

          .cta-box {
            margin-top: 94px;
            background: linear-gradient(135deg, #102544 0%, #183d7b 100%);
            border-radius: 30px;
            padding: 34px 30px;
            color: white;
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 26px;
            box-shadow: var(--shadow);
          }
          .cta-box h3 {
            margin: 0 0 8px;
            font-size: clamp(2rem, 3vw, 2.7rem);
            letter-spacing: -0.05em;
          }
          .cta-box p {
            margin: 0;
            color: rgba(255,255,255,0.8);
            line-height: 1.7;
          }

          footer {
            padding: 28px 0 40px;
            color: var(--muted);
          }
          .footer-box {
            border-top: 1px solid var(--line);
            padding-top: 24px;
            display: flex;
            justify-content: space-between;
            gap: 18px;
            flex-wrap: wrap;
          }

          @keyframes pulse {
            0%, 100% { transform: scale(1); opacity: 1; }
            50% { transform: scale(1.18); opacity: 0.8; }
          }
          @keyframes loading {
            0% { width: 0%; }
            100% { width: 100%; }
          }

          @media (max-width: 980px) {
            .hero-grid, .split, .feature-grid, .usecase-grid, .metrics-grid { grid-template-columns: 1fr 1fr; }
            .hero-grid { grid-template-columns: 1fr; }
            .architecture-flow { grid-template-columns: repeat(2, minmax(180px, 1fr)); }
          }

          @media (max-width: 720px) {
            .nav-links { display: none; }
            .feature-grid, .usecase-grid, .metrics-grid, .architecture-flow, .split { grid-template-columns: 1fr; }
            .mini-stats { grid-template-columns: 1fr; }
            .cta-box { flex-direction: column; align-items: flex-start; }
          }
        </style>
      </head>
      <body>
        <div class="loading-screen" id="loadingScreen">
          <div class="loader-box">
            <div class="loader-brand"><span class="loader-dot"></span> Universal Log Framework</div>
            <p class="loader-title">Initializing security telemetry</p>
            <div class="loader-bar"><div class="loader-fill"></div></div>
          </div>
        </div>

        <header class="topbar">
          <div class="container nav">
            <div class="brand">
              <span class="brand-mark"></span>
              <span>Universal Log Framework</span>
            </div>
            <nav class="nav-links" aria-label="Main navigation">
              <a href="#home">Home</a>
              <a href="#about">About</a>
              <a href="#features">Features</a>
              <a href="#architecture">Architecture</a>
              <a href="#impact">Impact</a>
            </nav>
            <div class="nav-actions">
              <a href="/dashboard" class="btn btn-secondary">Dashboard</a>
              <a href="/dashboard" class="btn btn-primary">Live Demo</a>
            </div>
          </div>
        </header>

        <main id="home">
          <section class="hero">
            <div class="container hero-grid">
              <div>
                <span class="eyebrow">Cybersecurity intelligence</span>
                <h1>Unified log intelligence for modern security operations.</h1>
                <p class="lead">
                  Universal Log Framework collects and processes cybersecurity logs from multiple heterogeneous sources,
                  automatically detects their format, parses raw events, normalizes them into a common schema, enriches
                  them with GeoIP and threat intelligence, validates each event, and exposes the results through an
                  operational dashboard and API.
                </p>
                <div class="cta-row">
                  <a href="/dashboard" class="btn btn-primary">Explore the platform</a>
                  <a href="#about" class="btn btn-secondary">Learn more</a>
                </div>
                <div class="mini-stats">
                  <div class="stat-box">
                    <div class="stat-label">Formats</div>
                    <div class="stat-value">5+</div>
                  </div>
                  <div class="stat-box">
                    <div class="stat-label">Sources</div>
                    <div class="stat-value">9</div>
                  </div>
                  <div class="stat-box">
                    <div class="stat-label">Coverage</div>
                    <div class="stat-value">93%</div>
                  </div>
                </div>
              </div>

              <div class="hero-visual">
                <div class="visual-top">
                  <strong>Security Overview</strong>
                  <span class="visual-pill">System live</span>
                </div>

                <div class="metric-grid">
                  <div class="mini-card">
                    <div class="label">Logs processed</div>
                    <div class="value">1.2k</div>
                  </div>
                  <div class="mini-card">
                    <div class="label">Threats</div>
                    <div class="value">18</div>
                  </div>
                  <div class="mini-card">
                    <div class="label">Blocked</div>
                    <div class="value">92</div>
                  </div>
                  <div class="mini-card">
                    <div class="label">Anomalies</div>
                    <div class="value">87%</div>
                  </div>
                </div>

                <div class="event-board">
                  <div class="event-row">
                    <strong>Firewall Event</strong>
                    <span>src=1.2.3.4</span>
                    <span class="tag red">High</span>
                  </div>
                  <div class="event-row">
                    <strong>Auth Attempt</strong>
                    <span>10.0.0.5</span>
                    <span class="tag amber">Medium</span>
                  </div>
                  <div class="event-row">
                    <strong>DNS Lookup</strong>
                    <span>8.8.8.8</span>
                    <span class="tag green">Safe</span>
                  </div>
                </div>
              </div>
            </div>
          </section>

          <section id="about">
            <div class="container">
              <div class="section-title">
                <h2>About the project</h2>
                <p>
                  Security teams are often flooded with fragmented telemetry from applications, devices, proxies,
                  firewalls, and cloud services. Each source emits data in different syntax and format, making
                  correlation difficult and delaying threat response. This project solves that issue by normalizing
                  the data and surfacing actionable security insights in a unified manner.
                </p>
              </div>
            </div>
          </section>

          <section>
            <div class="container">
              <div class="section-title">
                <h2>Why this project matters</h2>
                <p>Security visibility breaks down when telemetry is fragmented, inconsistent, and slow to analyze.</p>
              </div>
              <div class="metrics-grid">
                <div class="metric-card">
                  <h3>Fragmented sources</h3>
                  <p>Logs arrive from multiple vendors and environments in incompatible formats, creating blind spots.</p>
                </div>
                <div class="metric-card">
                  <h3>Threat correlation</h3>
                  <p>Disconnected events make it hard to connect suspicious behavior, geo-risk, or repeated attack patterns.</p>
                </div>
                <div class="metric-card">
                  <h3>Unified monitoring</h3>
                  <p>One normalized pipeline helps analysts identify risk faster and prioritize high-impact incidents.</p>
                </div>
              </div>
            </div>
          </section>

          <section id="features">
            <div class="container">
              <div class="section-title">
                <h2>Key features</h2>
                <p>Every stage of the workflow is designed to convert raw telemetry into meaningful, decision-ready threat intelligence.</p>
              </div>

              <div class="feature-grid">
                <div class="feature-card">
                  <div class="feature-icon">01</div>
                  <h3>Format detection</h3>
                  <p>Automatically identifies syslog, JSON, CEF, key-value, and other common security log styles.</p>
                </div>
                <div class="feature-card">
                  <div class="feature-icon">02</div>
                  <h3>Parsing</h3>
                  <p>Extracts relevant fields from complex, heterogeneous payloads with minimal manual intervention.</p>
                </div>
                <div class="feature-card">
                  <div class="feature-icon">03</div>
                  <h3>Normalization</h3>
                  <p>Maps every event to a common schema for consistent search, reporting, and correlation.</p>
                </div>
                <div class="feature-card">
                  <div class="feature-icon">04</div>
                  <h3>Enrichment</h3>
                  <p>Attaches GeoIP context and reputation intelligence to help spot suspicious activity quickly.</p>
                </div>
                <div class="feature-card">
                  <div class="feature-icon">05</div>
                  <h3>Validation</h3>
                  <p>Filters malformed or low-confidence events before they reach operational dashboards or APIs.</p>
                </div>
                <div class="feature-card">
                  <div class="feature-icon">06</div>
                  <h3>ML anomaly detection</h3>
                  <p>Scores risk patterns and prioritizes high-volume or unusual behavioral changes for investigation.</p>
                </div>
              </div>
            </div>
          </section>

          <section id="architecture">
            <div class="container">
              <div class="section-title">
                <h2>End-to-end architecture</h2>
                <p>The platform is structured as a continuous pipeline from ingestion to operational decision support.</p>
              </div>

              <div class="architecture-flow">
                <div class="process-card">
                  <div class="step-badge">1</div>
                  <h3>Ingestion</h3>
                  <p>Collect raw logs from diverse devices and systems.</p>
                </div>
                <div class="process-card">
                  <div class="step-badge">2</div>
                  <h3>Detection</h3>
                  <p>Identify log type automatically.</p>
                </div>
                <div class="process-card">
                  <div class="step-badge">3</div>
                  <h3>Parsing</h3>
                  <p>Extract structured key-value information.</p>
                </div>
                <div class="process-card">
                  <div class="step-badge">4</div>
                  <h3>Normalization</h3>
                  <p>Convert to a common canonical schema.</p>
                </div>
                <div class="process-card">
                  <div class="step-badge">5</div>
                  <h3>Enrichment</h3>
                  <p>Add geolocation and threat context.</p>
                </div>
                <div class="process-card">
                  <div class="step-badge">6</div>
                  <h3>Validation</h3>
                  <p>Ensure quality before alerting and storage.</p>
                </div>
                <div class="process-card">
                  <div class="step-badge">7</div>
                  <h3>Dashboard</h3>
                  <p>Present incidents through live operational views.</p>
                </div>
              </div>
            </div>
          </section>

          <section>
            <div class="container">
              <div class="section-title">
                <h2>How it works</h2>
                <p>The workflow reduces noise and accelerates high-confidence threat actionability.</p>
              </div>

              <div class="timeline">
                <div class="timeline-item">
                  <div class="timeline-number">01</div>
                  <div>
                    <h3>Collect events</h3>
                    <p>Gather data from endpoints, gateways, services, and monitoring infrastructure across the environment.</p>
                  </div>
                </div>
                <div class="timeline-item">
                  <div class="timeline-number">02</div>
                  <div>
                    <h3>Detect and parse</h3>
                    <p>Identify event format and decode the payloads into meaningful security fields.</p>
                  </div>
                </div>
                <div class="timeline-item">
                  <div class="timeline-number">03</div>
                  <div>
                    <h3>Normalize and validate</h3>
                    <p>Standardize the format and remove low-confidence or malformed activity before further processing.</p>
                  </div>
                </div>
                <div class="timeline-item">
                  <div class="timeline-number">04</div>
                  <div>
                    <h3>Correlate and prioritize</h3>
                    <p>Enhance with GeoIP and threat intelligence, then score risk and route to the operational dashboard.</p>
                  </div>
                </div>
              </div>
            </div>
          </section>

          <section>
            <div class="container split">
              <div class="half-card">
                <span class="eyebrow">Dashboard preview</span>
                <h2 style="margin: 16px 0 10px; font-size: clamp(1.9rem, 3vw, 2.7rem); letter-spacing: -0.05em;">Operational clarity for fast decisions.</h2>
                <p class="lead" style="max-width: none;">
                  The dashboard aggregates event flow, geo-risk, alert severity, and asset health in a single view,
                  helping analysts respond with confidence and speed.
                </p>
                <ul class="bullet-list">
                  <li><span class="bullet-dot"></span><span>Live KPI snapshots for logs, threats, blocked events, and anomaly coverage.</span></li>
                  <li><span class="bullet-dot"></span><span>Recent event table with severity labels, source identity, and suspicious network context.</span></li>
                  <li><span class="bullet-dot"></span><span>Asset health and incident panels that help prioritize investigation and remediation effort.</span></li>
                </ul>
              </div>

              <div class="half-card">
                <div class="event-board">
                  <div class="event-row"><strong>Threat IP</strong><span>1.2.3.4</span><span class="tag red">Critical</span></div>
                  <div class="event-row"><strong>Auth Failures</strong><span>10.0.0.5</span><span class="tag amber">High</span></div>
                  <div class="event-row"><strong>DNS Query</strong><span>8.8.8.8</span><span class="tag green">Low</span></div>
                  <div class="event-row"><strong>Portal Access</strong><span>web-01</span><span class="tag green">Healthy</span></div>
                </div>
              </div>
            </div>
          </section>

          <section>
            <div class="container">
              <div class="section-title">
                <h2>Use cases</h2>
                <p>Built for security teams seeking fast operational insight, broader visibility, and structured incident triage.</p>
              </div>
              <div class="usecase-grid">
                <div class="usecase-card">
                  <h3>SOC monitoring</h3>
                  <p>Keep a real-time view of suspicious events and incident progression across infrastructure and endpoint telemetry.</p>
                </div>
                <div class="usecase-card">
                  <h3>Log analytics</h3>
                  <p>Search and analyze native event patterns without losing context during cross-source correlation.</p>
                </div>
                <div class="usecase-card">
                  <h3>Threat investigation</h3>
                  <p>Trace source IPs, elevated-risk geographies, and suspicious outbound behaviors from a single interface.</p>
                </div>
              </div>
            </div>
          </section>

          <section>
            <div class="container">
              <div class="section-title">
                <h2>ML intelligence</h2>
                <p>Pattern learning helps prioritize anomalies and refine threat detection beyond simple rule-based checks.</p>
              </div>
              <div class="feature-grid">
                <div class="feature-card">
                  <div class="feature-icon">AI</div>
                  <h3>Anomaly detection</h3>
                  <p>Identify unusual traffic or login patterns based on normal activity baselines and score them.</p>
                </div>
                <div class="feature-card">
                  <div class="feature-icon">RS</div>
                  <h3>Risk scoring</h3>
                  <p>Assign weighted risk labels to event clusters so high-priority detections rise to the top.</p>
                </div>
                <div class="feature-card">
                  <div class="feature-icon">PR</div>
                  <h3>Prioritization</h3>
                  <p>Flag which incidents deserve immediate investigation, resource allocation, and response planning.</p>
                </div>
              </div>
            </div>
          </section>

          <section>
            <div class="container">
              <div class="section-title">
                <h2>Future scope</h2>
                <p>Planned platform growth focuses on broader coverage, smarter automation, and richer operational decision support.</p>
              </div>
              <div class="feature-grid">
                <div class="feature-card">
                  <div class="feature-icon">+</div>
                  <h3>Expanded integrations</h3>
                  <p>Add more log producers, SIEM connectors, and vendor-specific parsers to rise beyond the current baseline.</p>
                </div>
                <div class="feature-card">
                  <div class="feature-icon">⚡</div>
                  <h3>Automated response</h3>
                  <p>Introduce playbooks that trigger automated blocking, quarantine, or escalation steps when rules match.</p>
                </div>
                <div class="feature-card">
                  <div class="feature-icon">☁</div>
                  <h3>Cloud-ready scaling</h3>
                  <p>Enable large-scale deployment patterns for enterprise security monitoring and centralized visibility.</p>
                </div>
              </div>
            </div>
          </section>

          <section id="impact">
            <div class="container">
              <div class="section-title">
                <h2>Project impact</h2>
                <p>Designed to improve analyst efficiency, reduce investigation overhead, and create better security visibility across hybrid systems.</p>
              </div>
              <div class="feature-grid">
                <div class="feature-card">
                  <h3>Better SOC readiness</h3>
                  <p>Prepares organizations for more mature operational monitoring with actionable metrics and cleaner event pipelines.</p>
                </div>
                <div class="feature-card">
                  <h3>Faster triage</h3>
                  <p>Analysts can move from raw telemetry to incident prioritization with less context switching and less manual parsing.</p>
                </div>
                <div class="feature-card">
                  <h3>Enterprise credibility</h3>
                  <p>Presents a realistic cybersecurity product story that feels aligned with real-world SIEM and monitoring needs.</p>
                </div>
              </div>
            </div>
          </section>

          <div class="container">
            <div class="cta-box">
              <div>
                <h3>Build a smarter, unified security view.</h3>
                <p>Turn fragmented logs into a coherent operational picture with proactive detection and better threat visibility.</p>
              </div>
              <a href="/dashboard" class="btn btn-primary">Open live demo</a>
            </div>
          </div>
        </main>

        <footer>
          <div class="container footer-box">
            <div>
              <strong>Universal Log Framework</strong><br />
              Cybersecurity log normalization, enrichment, and operational intelligence platform.
            </div>
            <div>
              <a href="#features">Features</a> ·
              <a href="#architecture">Architecture</a> ·
              <a href="/dashboard">Dashboard</a>
            </div>
            <div>
              Project reference / demo environment
            </div>
          </div>
        </footer>

        <script>
          const loadingScreen = document.getElementById('loadingScreen');
          window.addEventListener('load', () => {
            setTimeout(() => loadingScreen.classList.add('hidden'), 700);
          });
        </script>
      </body>
    </html>
    """
    return HTMLResponse(content=html)


@app.get('/dashboard', response_class=HTMLResponse)
def dashboard():
    html = """
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Universal Log Framework</title>
        <style>
          :root {
            --bg: #f4f7fb;
            --bg-soft: #edf3ff;
            --panel: #ffffff;
            --panel-alt: #f8fbff;
            --line: #dfeaf7;
            --text: #122033;
            --muted: #60718a;
            --primary: #2b6ef5;
            --primary-soft: #eaf1ff;
            --green: #1dbf73;
            --green-soft: #ebfff5;
            --amber: #f4b942;
            --amber-soft: #fff7df;
            --red: #ea4b5f;
            --red-soft: #ffecef;
            --shadow: 0 18px 45px rgba(17, 37, 66, 0.08);
          }

          * { box-sizing: border-box; }
          html { scroll-behavior: smooth; }
          body {
            margin: 0;
            min-height: 100vh;
            font-family: Inter, "Segoe UI", sans-serif;
            background: linear-gradient(180deg, #f5f9ff 0%, #edf3fb 100%);
            color: var(--text);
          }

          .page { max-width: 1420px; margin: 0 auto; padding: 26px 22px 60px; }
          .topbar {
            display: flex; justify-content: space-between; align-items: center; padding: 18px 22px; border: 1px solid var(--line); border-radius: 22px; background: rgba(255,255,255,0.87); backdrop-filter: blur(8px); box-shadow: var(--shadow); position: sticky; top: 12px; z-index: 20;
          }
          .brand { display: flex; align-items: center; gap: 12px; font-weight: 800; letter-spacing: 0.06em; text-transform: uppercase; color: var(--primary); }
          .brand-mark { width: 12px; height: 12px; border-radius: 50%; background: linear-gradient(135deg, var(--primary), #74b3ff); box-shadow: 0 0 18px rgba(43,110,245,0.5); animation: pulse 2s infinite; }
          .nav { display: flex; gap: 18px; align-items: center; flex-wrap: wrap; }
          .nav a { color: var(--muted); text-decoration: none; font-size: 12px; letter-spacing: 0.08em; text-transform: uppercase; transition: color 0.2s ease; }
          .nav a:hover { color: var(--primary); }
          .status-pill { display: inline-flex; align-items: center; gap: 8px; padding: 8px 14px; border-radius: 999px; background: var(--primary-soft); color: var(--primary); border: 1px solid rgba(43,110,245,0.15); font-size: 11px; letter-spacing: 0.08em; text-transform: uppercase; font-weight: 700; }
          .status-pill::before { content: ""; width: 8px; height: 8px; border-radius: 50%; background: var(--green); box-shadow: 0 0 0 5px rgba(29, 191, 115, 0.12); }
          .hero { margin-top: 28px; display: grid; grid-template-columns: 1.2fr 0.8fr; gap: 22px; }
          .hero-card, .panel, .metric-card { background: var(--panel); border: 1px solid var(--line); border-radius: 20px; box-shadow: var(--shadow); animation: rise 0.5s ease both; }
          .hero-card { padding: 26px 24px; }
          .eyebrow { color: var(--primary); letter-spacing: 0.12em; text-transform: uppercase; font-size: 11px; font-weight: 700; margin-bottom: 16px; }
          h1 { margin: 0; font-size: clamp(2.3rem, 4vw, 4rem); line-height: 1.08; letter-spacing: -0.05em; }
          .headline-sub { margin-top: 16px; color: var(--muted); line-height: 1.75; font-size: 15px; max-width: 62ch; }
          .quick-actions { margin-top: 22px; display: flex; gap: 12px; flex-wrap: wrap; }
          button { border: none; border-radius: 12px; padding: 12px 18px; font-size: 14px; font-weight: 700; cursor: pointer; transition: transform 0.2s ease, box-shadow 0.2s ease; }
          button:hover { transform: translateY(-2px); box-shadow: 0 10px 18px rgba(43,110,245,0.12); }
          .primary { background: linear-gradient(135deg, var(--primary), #6a8dff); color: white; }
          .secondary { background: #f3f7ff; color: var(--text); border: 1px solid var(--line); }
          .mini-metrics { display: grid; grid-template-columns: repeat(2, minmax(130px, 1fr)); gap: 16px; margin-top: 20px; }
          .mini-box { background: var(--panel-alt); border: 1px solid var(--line); border-radius: 16px; padding: 16px 15px; }
          .mini-box .label { color: var(--muted); text-transform: uppercase; letter-spacing: 0.08em; font-size: 10px; }
          .mini-box .value { margin-top: 10px; font-size: 28px; font-weight: 800; }
          .monitor-stack { display: flex; flex-direction: column; gap: 12px; margin-top: 18px; }
          .monitor-item { display: flex; align-items: center; gap: 10px; padding: 14px 14px; border-radius: 14px; background: var(--panel-alt); border: 1px solid var(--line); color: var(--muted); }
          .monitor-item strong { color: var(--text); }
          .stats-grid { margin-top: 24px; display: grid; grid-template-columns: repeat(4, minmax(180px, 1fr)); gap: 18px; }
          .metric-card { padding: 18px 18px 16px; }
          .metric-card .label { color: var(--muted); font-size: 10px; letter-spacing: 0.1em; text-transform: uppercase; }
          .metric-card .value { font-size: 34px; font-weight: 800; margin-top: 14px; line-height: 1; }
          .metric-card .trend { margin-top: 10px; color: var(--green); font-size: 12px; }
          .content { margin-top: 26px; display: grid; grid-template-columns: 1.2fr 0.8fr; gap: 22px; }
          .panel { padding: 18px 18px 16px; }
          .panel-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; }
          .panel-title { margin: 0; font-size: 20px; letter-spacing: -0.02em; }
          textarea { width: 100%; min-height: 138px; padding: 16px; border: 1px solid var(--line); border-radius: 14px; background: #f9fbff; color: var(--text); font-family: 'SFMono-Regular', Consolas, monospace; font-size: 14px; resize: vertical; }
          .input-actions { display: flex; gap: 12px; margin-top: 14px; flex-wrap: wrap; }
          .list-block { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 12px; }
          .list-item { padding: 14px 14px; border: 1px solid var(--line); border-radius: 14px; background: var(--panel-alt); color: var(--muted); line-height: 1.6; }
          .list-item strong { color: var(--text); }
          .table-wrap { overflow-x: auto; }
          table { width: 100%; border-collapse: collapse; min-width: 600px; }
          th, td { text-align: left; padding: 12px 10px; border-bottom: 1px solid var(--line); font-size: 13px; }
          th { font-size: 10px; letter-spacing: 0.1em; text-transform: uppercase; color: var(--muted); }
          .badge { display: inline-flex; align-items: center; justify-content: center; padding: 6px 9px; border-radius: 999px; font-size: 10px; font-weight: 800; letter-spacing: 0.08em; text-transform: uppercase; }
          .badge.high { background: var(--red-soft); color: var(--red); }
          .badge.medium { background: var(--amber-soft); color: #b77d00; }
          .badge.low { background: var(--green-soft); color: var(--green); }
          .dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 8px; vertical-align: middle; }
          .dot.red { background: var(--red); }
          .dot.amber { background: var(--amber); }
          .dot.green { background: var(--green); }
          .dot.blue { background: var(--primary); }
          .lower-grid { margin-top: 24px; display: grid; grid-template-columns: 1fr 1fr; gap: 22px; }
          .score-card { display: flex; flex-direction: column; gap: 12px; }
          .score-row { display: flex; align-items: center; justify-content: space-between; padding: 12px 0; border-bottom: 1px solid var(--line); }
          .footer-note { margin-top: 14px; color: var(--muted); font-size: 12px; }
          @keyframes pulse { 0%, 100% { transform: scale(1); opacity: 1; } 50% { transform: scale(1.22); opacity: 0.82; } }
          @keyframes rise { from { opacity: 0; transform: translateY(12px); } to { opacity: 1; transform: translateY(0); } }
          @media (max-width: 980px) { .hero, .content, .lower-grid { grid-template-columns: 1fr; } .stats-grid { grid-template-columns: repeat(2, minmax(180px, 1fr)); } }
          @media (max-width: 640px) { .stats-grid { grid-template-columns: 1fr; } .nav { display: none; } .topbar { padding: 14px 16px; } }
        </style>
      </head>
      <body>
        <div class="page">
          <header class="topbar">
            <div class="brand"><span class="brand-mark"></span><span>Universal Log Framework</span></div>
            <nav class="nav" aria-label="Main navigation">
              <a href="#overview">Overview</a>
              <a href="#threats">Threats</a>
              <a href="#assets">Assets</a>
              <a href="#logs">Log Feed</a>
              <a href="#incidents">Incidents</a>
            </nav>
            <div class="status-pill">Live SOC</div>
          </header>

          <section class="hero" id="overview">
            <div class="hero-card">
              <div class="eyebrow">SIH Security Intelligence</div>
              <h1>Unified security data across every log source.</h1>
              <div class="headline-sub">Aggregate syslog, JSON, CEF, and standardized security events into one low-friction operational view for investigation, detection, and guided response.</div>
              <div class="quick-actions">
                <button class="primary" onclick="document.getElementById('logInput').focus()">Process Log</button>
                <button class="secondary" onclick="loadSample()">Load Demo Threat</button>
              </div>
              <div class="mini-metrics">
                <div class="mini-box"><div class="label">Event Types</div><div class="value" id="mini-types">0</div></div>
                <div class="mini-box"><div class="label">Active Sources</div><div class="value" id="mini-sources">0</div></div>
                <div class="mini-box"><div class="label">Detection Rate</div><div class="value">93%</div></div>
                <div class="mini-box"><div class="label">Avg. Response</div><div class="value">105ms</div></div>
              </div>
            </div>

            <div class="hero-card">
              <div class="eyebrow">Threat Overview</div>
              <div class="monitor-stack">
                <div class="monitor-item"><span class="dot red"></span><strong>Blocked:</strong> External IP attempted access to critical workloads.</div>
                <div class="monitor-item"><span class="dot amber"></span><strong>Warning:</strong> SSH password spray activity is trending above baseline.</div>
                <div class="monitor-item"><span class="dot green"></span><strong>Healthy:</strong> Public DNS and trusted infrastructure remain stable.</div>
                <div class="monitor-item"><span class="dot blue"></span><strong>Context:</strong> GeoIP and reputation scoring continue to enrich events.</div>
              </div>
              <div class="footer-note">The framework normalizes and validates events before exposing them to dashboards and APIs.</div>
            </div>
          </section>

          <section class="stats-grid">
            <div class="metric-card"><div class="label">Logs Processed</div><div class="value" id="count-total">0</div><div class="trend">+12% vs last hour</div></div>
            <div class="metric-card"><div class="label">Threats</div><div class="value" id="count-threats">0</div><div class="trend">2 high severity</div></div>
            <div class="metric-card"><div class="label">Blocked</div><div class="value" id="count-blocked">0</div><div class="trend">policy-based controls</div></div>
            <div class="metric-card"><div class="label">Sources</div><div class="value" id="count-sources">0</div><div class="trend">multi-vendor telemetry</div></div>
          </section>

          <section class="content" id="logs">
            <div class="panel">
              <div class="panel-header"><h2 class="panel-title">Log Ingestion</h2></div>
              <textarea id="logInput" placeholder="Paste a syslog, JSON, CEF, or key=value security event...">src=10.0.0.5 dst=8.8.8.8 action=deny</textarea>
              <div class="input-actions">
                <button class="primary" onclick="submitLog()">Process Log</button>
                <button class="secondary" onclick="loadSample()">Load Demo Input</button>
              </div>
            </div>
            <div class="panel" id="threats">
              <div class="panel-header"><h2 class="panel-title">Security Pulse</h2></div>
              <ul class="list-block" id="alertList"></ul>
            </div>
          </section>

          <section class="lower-grid">
            <div class="panel" id="assets"><div class="panel-header"><h2 class="panel-title">Asset Health</h2></div><div id="assetsList" class="score-card"></div></div>
            <div class="panel" id="incidents"><div class="panel-header"><h2 class="panel-title">Priority Incidents</h2></div><div id="incidentList" class="score-card"></div></div>
          </section>

          <section class="panel" style="margin-top: 22px;">
            <div class="panel-header"><h2 class="panel-title">Recent Security Events</h2></div>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr><th>Timestamp</th><th>Source</th><th>Action</th><th>Severity</th><th>IP</th><th>Threat</th></tr>
                </thead>
                <tbody id="eventTable"></tbody>
              </table>
            </div>
          </section>
        </div>

        <script>
          async function refreshData() {
            const summary = await fetch('/summary').then(r => r.json());
            const overview = await fetch('/api/overview').then(r => r.json());
            const events = await fetch('/events').then(r => r.json());
            const ml = await fetch('/api/ml/insights').then(r => r.json());
            const total = summary.total_events || events.length;
            const blocked = summary.blocked_events || 0;
            const sources = new Set((summary.sources || []).concat(events.map(e => e.source || 'unknown'))).size;

            document.getElementById('count-total').textContent = total;
            document.getElementById('count-threats').textContent = `${Math.round((ml.anomaly_score || 0) * 100)}%`;
            document.getElementById('count-blocked').textContent = blocked;
            document.getElementById('count-sources').textContent = sources;
            document.getElementById('mini-types').textContent = new Set(events.map(e => (e.event && e.event.type) || 'unknown')).size;
            document.getElementById('mini-sources').textContent = sources;

            const tbody = document.getElementById('eventTable');
            tbody.innerHTML = events.slice().reverse().slice(0, 8).map((event) => {
              const source = event.source || 'unknown';
              const action = (event.event && event.event.action) || 'unknown';
              const severity = (event.event && event.event.severity) || 'low';
              const ip = (event.network && (event.network.source_ip || event.network.destination_ip)) || 'unknown';
              const threat = (event.threat && event.threat.reputation) || 'unknown';
              const badgeClass = severity.toLowerCase() === 'critical' || severity.toLowerCase() === 'high' ? 'high' : severity.toLowerCase() === 'medium' ? 'medium' : 'low';
              return `<tr><td>${event.timestamp || '—'}</td><td>${source}</td><td>${action}</td><td><span class="badge ${badgeClass}">${severity}</span></td><td>${ip}</td><td>${threat}</td></tr>`;
            }).join('');

            const alerts = overview.alerts || [];
            document.getElementById('alertList').innerHTML = alerts.map((alert) => {
              const level = (alert.severity || 'medium').toLowerCase();
              const className = level === 'high' ? 'red' : level === 'medium' ? 'amber' : 'green';
              return `<li class="list-item"><span class="dot ${className}"></span><strong>${alert.title}</strong><br>${alert.summary}</li>`;
            }).join('');

            const assets = overview.assets || [];
            document.getElementById('assetsList').innerHTML = assets.map(item => `<div class="score-row"><strong>${item.name}</strong><span class="badge ${item.risk === 'high' ? 'high' : item.risk === 'medium' ? 'medium' : 'low'}">${item.status}</span></div>`).join('');

            const incidents = overview.incidents || [];
            document.getElementById('incidentList').innerHTML = incidents.map(item => `<div class="score-row"><div><strong>${item.title}</strong><div class="footer-note">${item.severity}</div></div><div class="badge ${item.severity === 'high' ? 'high' : item.severity === 'medium' ? 'medium' : 'low'}">${item.score}</div></div>`).join('');
          }

          async function submitLog() {
            const input = document.getElementById('logInput').value.trim();
            if (!input) return;
            const response = await fetch('/logs', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ log: input }) });
            const result = await response.json();
            if (result && (result.network || result.event)) refreshData();
          }

          function loadSample() {
            document.getElementById('logInput').value = 'src=1.2.3.4 dst=8.8.8.8 action=deny';
          }

          refreshData();
          setInterval(refreshData, 5000);
        </script>
      </body>
    </html>
    """
    return HTMLResponse(content=html)


@app.get('/health')
def health():
    uptime_seconds = max(0, int(time.time() - START_TIME))
    return {
        'status': 'ok',
        'service': 'universal-log-framework',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'uptime_seconds': uptime_seconds,
        'total_events': len(EVENT_STORE),
        'sources': _get_sources(EVENT_STORE),
    }


@app.get('/summary')
def summary():
    return _build_summary(EVENT_STORE)


@app.get('/api/summary')
def api_summary():
    return _build_summary(EVENT_STORE)


@app.get('/api/overview')
def api_overview():
    return _build_overview()


@app.get('/api/alerts')
def api_alerts():
    return _build_dynamic_alerts(EVENT_STORE)


@app.get('/api/incidents')
def api_incidents():
    return _build_dynamic_incidents(EVENT_STORE)


@app.get('/api/assets')
def api_assets():
    return _build_dynamic_assets(EVENT_STORE)


@app.get('/api/ml/insights')
def api_ml_insights():
    return get_ml_insights(EVENT_STORE)


@app.get('/events')
def get_events():
    return EVENT_STORE


@app.post('/logs')
def ingest_log(payload: dict):
    raw_log = payload.get('log') or payload.get('message') or ''
    if not raw_log:
        return {'error': 'No log payload provided'}
    return process_log_payload(raw_log)


@app.post('/api/logs/batch')
def ingest_batch_logs(payload: dict):
    logs = payload.get('logs') or []
    results = []

    # SHA-256 Audit Backup for the complete file/batch stream
    full_text = "\n".join(l for l in logs if isinstance(l, str) and l.strip())
    if full_text:
        audit_and_backup_raw_log(full_text, source='file_batch_upload')

    for raw_log in logs:
        if isinstance(raw_log, str) and raw_log.strip():
            results.append(process_log_payload(raw_log.strip()))
    return results


@app.post('/api/events/clear')
def clear_events():
    count = len(EVENT_STORE)
    EVENT_STORE.clear()
    return {'message': 'Event store cleared', 'count': count}


@app.get('/api/v1/audit/logs')
@app.get('/api/audit/logs')
def get_audit_trail_logs(limit: int = 50):
    return get_audit_logs(limit)


@app.get('/api/v1/quarantine')
@app.get('/api/quarantine')
def get_quarantine_vault_items(limit: int = 50):
    return get_quarantine_items(limit)


@app.post('/api/v1/quarantine/action')
@app.post('/api/quarantine/action')
def quarantine_action(payload: dict):
    quarantine_id = payload.get('quarantine_id') or ''
    action = payload.get('action') or 'release'
    return process_quarantine_action(quarantine_id, action)


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print('Usage: python -m app.main <logfile>')
        raise SystemExit(1)
    path = Path(sys.argv[1])
    events = process_log_file(str(path))
    print(json.dumps(events, indent=2))
