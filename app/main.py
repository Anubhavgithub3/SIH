import json
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, RedirectResponse

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
START_TIME = time.time()

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


def _build_overview():
    summary = _build_summary(EVENT_STORE)
    alerts = [
        {
            'title': 'C2 beaconing detected',
            'severity': 'high',
            'source': '1.2.3.4',
            'summary': 'Outbound beacon pattern for 9 minutes observed in firewall telemetry.',
        },
        {
            'title': 'Failed admin logins',
            'severity': 'medium',
            'source': '10.0.0.5',
            'summary': 'Repeated authentication failures on privileged account across SSH surface.',
        },
        {
            'title': 'Geo-risk flagged',
            'severity': 'low',
            'source': 'CN',
            'summary': 'Traffic from elevated-risk geography matched historical suspicious activity.',
        },
    ]
    incidents = [
        {'title': 'Malicious outbound connection', 'severity': 'high', 'score': 92},
        {'title': 'Repeated authentication failures', 'severity': 'medium', 'score': 68},
        {'title': 'Unusual geo access', 'severity': 'low', 'score': 47},
    ]
    assets = [
        {'name': 'web-01', 'status': 'healthy', 'risk': 'low', 'owner': 'Platform'},
        {'name': 'api-gateway', 'status': 'watch', 'risk': 'medium', 'owner': 'Security'},
        {'name': 'db-prod-02', 'status': 'critical', 'risk': 'high', 'owner': 'Data'},
    ]
    return {
        'summary': summary,
        'alerts': alerts,
        'incidents': incidents,
        'assets': assets,
        'events': EVENT_STORE[:8],
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
    parsed_events = _parse_raw(raw_text)
    normalized = []
    for event in parsed_events:
        normal = normalize_event(event, source='api')
        normal = enrich_geoip(normal)
        normal = enrich_threat_intel(normal)
        normalized.append(normal)
    valid = validate_events(normalized)
    result = valid[0] if valid else {'event': {'type': 'unknown'}, 'metadata': {'processing_status': 'unparsed'}, 'raw_log': raw_text}
    EVENT_STORE.append(result)
    return result


def process_log_file(file_path: str):
    raw_text = read_log_file(file_path)
    parsed_events = _parse_raw(raw_text)
    normalized = []
    for event in parsed_events:
        normal = normalize_event(event, source='file')
        normal = enrich_geoip(normal)
        normal = enrich_threat_intel(normal)
        if normal.get('event', {}).get('message') or normal.get('metadata'):
            normalized.append(normal)
    return validate_events(normalized)


@app.get('/')
def root():
    return RedirectResponse(url='/dashboard')


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

          .page {
            max-width: 1420px;
            margin: 0 auto;
            padding: 26px 22px 60px;
          }

          .topbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 18px 22px;
            border: 1px solid var(--line);
            border-radius: 22px;
            background: rgba(255,255,255,0.87);
            backdrop-filter: blur(8px);
            box-shadow: var(--shadow);
            position: sticky;
            top: 12px;
            z-index: 20;
          }

          .brand {
            display: flex;
            align-items: center;
            gap: 12px;
            font-weight: 800;
            letter-spacing: 0.06em;
            text-transform: uppercase;
            color: var(--primary);
          }

          .brand-mark {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: linear-gradient(135deg, var(--primary), #74b3ff);
            box-shadow: 0 0 18px rgba(43,110,245,0.5);
            animation: pulse 2s infinite;
          }

          .nav {
            display: flex;
            gap: 18px;
            align-items: center;
            flex-wrap: wrap;
          }

          .nav a {
            color: var(--muted);
            text-decoration: none;
            font-size: 12px;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            transition: color 0.2s ease;
          }

          .nav a:hover { color: var(--primary); }

          .status-pill {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 8px 14px;
            border-radius: 999px;
            background: var(--primary-soft);
            color: var(--primary);
            border: 1px solid rgba(43,110,245,0.15);
            font-size: 11px;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            font-weight: 700;
          }

          .status-pill::before {
            content: "";
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--green);
            box-shadow: 0 0 0 5px rgba(29, 191, 115, 0.12);
          }

          .hero {
            margin-top: 28px;
            display: grid;
            grid-template-columns: 1.2fr 0.8fr;
            gap: 22px;
          }

          .hero-card, .panel, .metric-card {
            background: var(--panel);
            border: 1px solid var(--line);
            border-radius: 20px;
            box-shadow: var(--shadow);
            animation: rise 0.5s ease both;
          }

          .hero-card { padding: 26px 24px; }

          .eyebrow {
            color: var(--primary);
            letter-spacing: 0.12em;
            text-transform: uppercase;
            font-size: 11px;
            font-weight: 700;
            margin-bottom: 16px;
          }

          h1 {
            margin: 0;
            font-size: clamp(2.3rem, 4vw, 4rem);
            line-height: 1.08;
            letter-spacing: -0.05em;
          }

          .headline-sub {
            margin-top: 16px;
            color: var(--muted);
            line-height: 1.75;
            font-size: 15px;
            max-width: 62ch;
          }

          .quick-actions {
            margin-top: 22px;
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
          }

          button {
            border: none;
            border-radius: 12px;
            padding: 12px 18px;
            font-size: 14px;
            font-weight: 700;
            cursor: pointer;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
          }

          button:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 18px rgba(43,110,245,0.12);
          }

          .primary {
            background: linear-gradient(135deg, var(--primary), #6a8dff);
            color: white;
          }

          .secondary {
            background: #f3f7ff;
            color: var(--text);
            border: 1px solid var(--line);
          }

          .mini-metrics {
            display: grid;
            grid-template-columns: repeat(2, minmax(130px, 1fr));
            gap: 16px;
            margin-top: 20px;
          }

          .mini-box {
            background: var(--panel-alt);
            border: 1px solid var(--line);
            border-radius: 16px;
            padding: 16px 15px;
          }

          .mini-box .label {
            color: var(--muted);
            text-transform: uppercase;
            letter-spacing: 0.08em;
            font-size: 10px;
          }

          .mini-box .value {
            margin-top: 10px;
            font-size: 28px;
            font-weight: 800;
          }

          .monitor-stack {
            display: flex;
            flex-direction: column;
            gap: 12px;
            margin-top: 18px;
          }

          .monitor-item {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 14px 14px;
            border-radius: 14px;
            background: var(--panel-alt);
            border: 1px solid var(--line);
            color: var(--muted);
          }

          .monitor-item strong { color: var(--text); }

          .stats-grid {
            margin-top: 24px;
            display: grid;
            grid-template-columns: repeat(4, minmax(180px, 1fr));
            gap: 18px;
          }

          .metric-card { padding: 18px 18px 16px; }

          .metric-card .label {
            color: var(--muted);
            font-size: 10px;
            letter-spacing: 0.1em;
            text-transform: uppercase;
          }

          .metric-card .value {
            font-size: 34px;
            font-weight: 800;
            margin-top: 14px;
            line-height: 1;
          }

          .metric-card .trend {
            margin-top: 10px;
            color: var(--green);
            font-size: 12px;
          }

          .content {
            margin-top: 26px;
            display: grid;
            grid-template-columns: 1.2fr 0.8fr;
            gap: 22px;
          }

          .panel { padding: 18px 18px 16px; }

          .panel-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 16px;
          }

          .panel-title {
            margin: 0;
            font-size: 20px;
            letter-spacing: -0.02em;
          }

          textarea {
            width: 100%;
            min-height: 138px;
            padding: 16px;
            border: 1px solid var(--line);
            border-radius: 14px;
            background: #f9fbff;
            color: var(--text);
            font-family: 'SFMono-Regular', Consolas, monospace;
            font-size: 14px;
            resize: vertical;
          }

          .input-actions {
            display: flex;
            gap: 12px;
            margin-top: 14px;
            flex-wrap: wrap;
          }

          .list-block {
            list-style: none;
            margin: 0;
            padding: 0;
            display: flex;
            flex-direction: column;
            gap: 12px;
          }

          .list-item {
            padding: 14px 14px;
            border: 1px solid var(--line);
            border-radius: 14px;
            background: var(--panel-alt);
            color: var(--muted);
            line-height: 1.6;
          }

          .list-item strong { color: var(--text); }

          .table-wrap { overflow-x: auto; }
          table {
            width: 100%;
            border-collapse: collapse;
            min-width: 600px;
          }

          th, td {
            text-align: left;
            padding: 12px 10px;
            border-bottom: 1px solid var(--line);
            font-size: 13px;
          }

          th {
            font-size: 10px;
            letter-spacing: 0.1em;
            text-transform: uppercase;
            color: var(--muted);
          }

          .badge {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 6px 9px;
            border-radius: 999px;
            font-size: 10px;
            font-weight: 800;
            letter-spacing: 0.08em;
            text-transform: uppercase;
          }

          .badge.high { background: var(--red-soft); color: var(--red); }
          .badge.medium { background: var(--amber-soft); color: #b77d00; }
          .badge.low { background: var(--green-soft); color: var(--green); }

          .dot {
            display: inline-block;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            margin-right: 8px;
            vertical-align: middle;
          }

          .dot.red { background: var(--red); }
          .dot.amber { background: var(--amber); }
          .dot.green { background: var(--green); }
          .dot.blue { background: var(--primary); }

          .lower-grid {
            margin-top: 24px;
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 22px;
          }

          .score-card { display: flex; flex-direction: column; gap: 12px; }
          .score-row {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 12px 0;
            border-bottom: 1px solid var(--line);
          }

          .footer-note {
            margin-top: 14px;
            color: var(--muted);
            font-size: 12px;
          }

          @keyframes pulse {
            0%, 100% { transform: scale(1); opacity: 1; }
            50% { transform: scale(1.22); opacity: 0.82; }
          }

          @keyframes rise {
            from { opacity: 0; transform: translateY(12px); }
            to { opacity: 1; transform: translateY(0); }
          }

          @media (max-width: 980px) {
            .hero, .content, .lower-grid { grid-template-columns: 1fr; }
            .stats-grid { grid-template-columns: repeat(2, minmax(180px, 1fr)); }
          }

          @media (max-width: 640px) {
            .stats-grid { grid-template-columns: 1fr; }
            .nav { display: none; }
            .topbar { padding: 14px 16px; }
          }
        </style>
      </head>
      <body>
        <div class="page">
          <header class="topbar">
            <div class="brand">
              <span class="brand-mark"></span>
              <span>Universal Log Framework</span>
            </div>
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
              <div class="headline-sub">
                Aggregate syslog, JSON, CEF, and standardized security events into one low-friction operational view for investigation, detection, and guided response.
              </div>
              <div class="quick-actions">
                <button class="primary" onclick="document.getElementById('logInput').focus()">Process Log</button>
                <button class="secondary" onclick="loadSample()">Load Demo Threat</button>
              </div>

              <div class="mini-metrics">
                <div class="mini-box">
                  <div class="label">Event Types</div>
                  <div class="value" id="mini-types">0</div>
                </div>
                <div class="mini-box">
                  <div class="label">Active Sources</div>
                  <div class="value" id="mini-sources">0</div>
                </div>
                <div class="mini-box">
                  <div class="label">Detection Rate</div>
                  <div class="value">93%</div>
                </div>
                <div class="mini-box">
                  <div class="label">Avg. Response</div>
                  <div class="value">105ms</div>
                </div>
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
            <div class="metric-card">
              <div class="label">Logs Processed</div>
              <div class="value" id="count-total">0</div>
              <div class="trend">+12% vs last hour</div>
            </div>
            <div class="metric-card">
              <div class="label">Threats</div>
              <div class="value" id="count-threats">0</div>
              <div class="trend">2 high severity</div>
            </div>
            <div class="metric-card">
              <div class="label">Blocked</div>
              <div class="value" id="count-blocked">0</div>
              <div class="trend">policy-based controls</div>
            </div>
            <div class="metric-card">
              <div class="label">Sources</div>
              <div class="value" id="count-sources">0</div>
              <div class="trend">multi-vendor telemetry</div>
            </div>
          </section>

          <section class="content" id="logs">
            <div class="panel">
              <div class="panel-header">
                <h2 class="panel-title">Log Ingestion</h2>
              </div>
              <textarea id="logInput" placeholder="Paste a syslog, JSON, CEF, or key=value security event...">src=10.0.0.5 dst=8.8.8.8 action=deny</textarea>
              <div class="input-actions">
                <button class="primary" onclick="submitLog()">Process Log</button>
                <button class="secondary" onclick="loadSample()">Load Demo Input</button>
              </div>
            </div>

            <div class="panel" id="threats">
              <div class="panel-header">
                <h2 class="panel-title">Security Pulse</h2>
              </div>
              <ul class="list-block" id="alertList"></ul>
            </div>
          </section>

          <section class="lower-grid">
            <div class="panel" id="assets">
              <div class="panel-header">
                <h2 class="panel-title">Asset Health</h2>
              </div>
              <div id="assetsList" class="score-card"></div>
            </div>

            <div class="panel" id="incidents">
              <div class="panel-header">
                <h2 class="panel-title">Priority Incidents</h2>
              </div>
              <div id="incidentList" class="score-card"></div>
            </div>
          </section>

          <section class="panel" style="margin-top: 22px;">
            <div class="panel-header">
              <h2 class="panel-title">Recent Security Events</h2>
            </div>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Source</th>
                    <th>Action</th>
                    <th>Severity</th>
                    <th>IP</th>
                    <th>Threat</th>
                  </tr>
                </thead>
                <tbody id="eventTable"></tbody>
              </table>
            </div>
          </section>
        </div>

        <script>
          async function refreshData() {
            const summaryResponse = await fetch('/summary');
            const overviewResponse = await fetch('/api/overview');
            const summary = await summaryResponse.json();
            const overview = await overviewResponse.json();
            const events = await fetch('/events').then(r => r.json());
            const ml = await fetch('/api/ml/insights').then(r => r.json());

            const total = summary.total_events || events.length;
            const threats = summary.high_severity || 0;
            const blocked = summary.blocked_events || 0;
            const sources = new Set((summary.sources || []).concat(events.map(e => e.source || 'unknown'))).size;

            document.getElementById('count-threats').textContent = `${Math.max(threats, Math.round(ml.anomaly_score * 10))}`;

            document.getElementById('count-total').textContent = total;
            document.getElementById('count-blocked').textContent = blocked;
            document.getElementById('count-sources').textContent = sources;
            document.getElementById('mini-types').textContent = new Set(events.map(e => (e.event && e.event.type) || 'unknown')).size;
            document.getElementById('mini-sources').textContent = sources;
            const mlLabel = ml.threat_label || 'benign';
            const mlBadge = mlLabel === 'critical' ? 'high' : mlLabel === 'suspicious' ? 'medium' : 'low';
            document.getElementById('count-threats').textContent = `${Math.round((ml.anomaly_score || 0) * 100)}%`;
            const threatOverview = document.getElementById('threats');
            if (threatOverview) {
              threatOverview.querySelector('.panel-header').insertAdjacentHTML('beforeend', ` <span class="badge ${mlBadge}">${mlLabel.toUpperCase()}</span>`);
            }

            const tbody = document.getElementById('eventTable');
            tbody.innerHTML = events.slice().reverse().slice(0, 8).map((event) => {
              const source = event.source || 'unknown';
              const action = (event.event && event.event.action) || 'unknown';
              const severity = (event.event && event.event.severity) || 'low';
              const ip = (event.network && (event.network.source_ip || event.network.destination_ip)) || 'unknown';
              const threat = (event.threat && event.threat.reputation) || 'unknown';
              const badgeClass = severity.toLowerCase() === 'critical' || severity.toLowerCase() === 'high' ? 'high' : severity.toLowerCase() === 'medium' ? 'medium' : 'low';
              return `
                <tr>
                  <td>${event.timestamp || '—'}</td>
                  <td>${source}</td>
                  <td>${action}</td>
                  <td><span class="badge ${badgeClass}">${severity}</span></td>
                  <td>${ip}</td>
                  <td>${threat}</td>
                </tr>
              `;
            }).join('');

            const alerts = overview.alerts || [];
            const alertList = document.getElementById('alertList');
            alertList.innerHTML = alerts.map((alert) => {
              const level = (alert.severity || 'medium').toLowerCase();
              const className = level === 'high' ? 'red' : level === 'medium' ? 'amber' : 'green';
              return `
                <li class="list-item"><span class="dot ${className}"></span><strong>${alert.title}</strong><br>${alert.summary}</li>
              `;
            }).join('');

            const assets = overview.assets || [];
            const assetsList = document.getElementById('assetsList');
            assetsList.innerHTML = assets.map(item => `
              <div class="score-row">
                <strong>${item.name}</strong>
                <span class="badge ${item.risk === 'high' ? 'high' : item.risk === 'medium' ? 'medium' : 'low'}">${item.status}</span>
              </div>
            `).join('');

            const incidents = overview.incidents || [];
            document.getElementById('incidentList').innerHTML = incidents.map(item => `
              <div class="score-row">
                <div>
                  <strong>${item.title}</strong>
                  <div class="footer-note">${item.severity}</div>
                </div>
                <div class="badge ${item.severity === 'high' ? 'high' : item.severity === 'medium' ? 'medium' : 'low'}">${item.score}</div>
              </div>
            `).join('');
          }

          async function submitLog() {
            const input = document.getElementById('logInput').value.trim();
            if (!input) return;
            const response = await fetch('/logs', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ log: input })
            });
            const result = await response.json();
            if (result && (result.network || result.event)) {
              refreshData();
            }
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
    return [
        {'title': 'C2 beaconing detected', 'severity': 'high', 'source': '1.2.3.4', 'summary': 'External host established repeated outbound connections to a suspicious remote endpoint.'},
        {'title': 'Failed admin logins', 'severity': 'medium', 'source': '10.0.0.5', 'summary': 'Privileged SSH failures exceeded threshold across multiple identity checks.'},
        {'title': 'Geo-risk flagged', 'severity': 'low', 'source': 'CN', 'summary': 'Traffic from a high-risk region matched historical threat intelligence data.'},
    ]


@app.get('/api/incidents')
def api_incidents():
    return [
        {'title': 'Malicious outbound connection', 'severity': 'high', 'score': 92},
        {'title': 'Repeated authentication failures', 'severity': 'medium', 'score': 68},
        {'title': 'Geo-anomaly on internal portal', 'severity': 'low', 'score': 47},
    ]


@app.get('/api/assets')
def api_assets():
    return [
        {'name': 'web-01', 'status': 'healthy', 'risk': 'low', 'owner': 'Platform'},
        {'name': 'api-gateway', 'status': 'watch', 'risk': 'medium', 'owner': 'Security'},
        {'name': 'db-prod-02', 'status': 'critical', 'risk': 'high', 'owner': 'Data'},
    ]


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


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print('Usage: python -m app.main <logfile>')
        raise SystemExit(1)
    path = Path(sys.argv[1])
    events = process_log_file(str(path))
    print(json.dumps(events, indent=2))
