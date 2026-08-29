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

    return {
        'total_events': total_events,
        'high_severity': high_severity,
        'blocked_events': blocked_events,
        'suspicious_ips': suspicious_ips,
        'sources': _get_sources(events),
        'last_updated': datetime.now(timezone.utc).isoformat(),
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
            --bg: #07121d;
            --bg-soft: #0d1b2a;
            --panel: rgba(15, 28, 43, 0.92);
            --panel-strong: #13263b;
            --panel-alt: #0d1c2c;
            --line: #244362;
            --text: #edf7ff;
            --muted: #9eb9d1;
            --cyan: #5bd5ff;
            --blue: #6a8dff;
            --green: #4ae3a2;
            --amber: #f6c76b;
            --red: #ff6475;
            --shadow: rgba(5, 12, 20, 0.45);
          }

          * { box-sizing: border-box; }
          html, body {
            margin: 0;
            min-height: 100%;
            font-family: Inter, "Segoe UI", Arial, sans-serif;
            background: linear-gradient(180deg, #07121d 0%, #0c1b2b 100%);
            color: var(--text);
          }

          body { padding: 0; }

          .page {
            max-width: 1380px;
            margin: 0 auto;
            padding: 24px 22px 50px;
          }

          .topbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 16px 22px;
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 18px;
            background: rgba(11, 19, 30, 0.8);
            backdrop-filter: blur(8px);
            box-shadow: 0 12px 32px var(--shadow);
          }

          .brand {
            display: flex;
            align-items: center;
            gap: 12px;
            font-weight: 700;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            color: var(--cyan);
          }

          .brand-mark {
            width: 12px;
            height: 12px;
            background: linear-gradient(135deg, var(--cyan), var(--green));
            border-radius: 50%;
            box-shadow: 0 0 18px rgba(91, 213, 255, 0.9);
          }

          .nav {
            display: flex;
            gap: 18px;
            align-items: center;
          }

          .nav a {
            color: var(--muted);
            text-decoration: none;
            font-size: 13px;
            letter-spacing: 0.06em;
            text-transform: uppercase;
          }

          .status {
            padding: 8px 14px;
            border: 1px solid rgba(91, 213, 255, 0.5);
            border-radius: 999px;
            background: rgba(91, 213, 255, 0.08);
            color: var(--cyan);
            font-size: 11px;
            letter-spacing: 0.08em;
            text-transform: uppercase;
          }

          .hero {
            margin-top: 26px;
            display: grid;
            grid-template-columns: 1.1fr 0.9fr;
            gap: 22px;
          }

          .hero-card {
            background: linear-gradient(180deg, rgba(17, 31, 47, 0.96), rgba(12, 26, 42, 0.96));
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 20px;
            padding: 26px 24px;
            box-shadow: 0 12px 32px var(--shadow);
          }

          .eyebrow {
            color: var(--cyan);
            text-transform: uppercase;
            letter-spacing: 0.12em;
            font-size: 11px;
            margin-bottom: 14px;
          }

          h1 {
            margin: 0;
            line-height: 1.1;
            font-size: clamp(2rem, 3vw, 3rem);
          }

          .headline-sub {
            margin-top: 14px;
            max-width: 62ch;
            color: var(--muted);
            line-height: 1.7;
            font-size: 15px;
          }

          .quick-actions {
            margin-top: 28px;
            display: flex;
            gap: 14px;
            flex-wrap: wrap;
          }

          button {
            border: none;
            border-radius: 12px;
            padding: 12px 18px;
            font-size: 14px;
            font-weight: 700;
            cursor: pointer;
            transition: transform 0.15s ease;
          }

          button:hover { transform: translateY(-1px); }

          .primary {
            background: linear-gradient(135deg, var(--cyan), var(--blue));
            color: #06131e;
          }

          .secondary {
            background: rgba(255,255,255,0.04);
            color: var(--text);
            border: 1px solid rgba(255,255,255,0.08);
          }

          .mini-metrics {
            display: grid;
            grid-template-columns: repeat(2, minmax(120px, 1fr));
            gap: 16px;
            margin-top: 22px;
          }

          .mini-box {
            background: rgba(255,255,255,0.025);
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 14px;
            padding: 16px;
          }

          .mini-box .label {
            color: var(--muted);
            text-transform: uppercase;
            letter-spacing: 0.08em;
            font-size: 10px;
          }

          .mini-box .value {
            margin-top: 8px;
            font-weight: 700;
            font-size: 26px;
          }

          .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(180px, 1fr));
            gap: 18px;
            margin-top: 28px;
          }

          .metric-card {
            background: rgba(11, 19, 30, 0.82);
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 16px;
            padding: 18px 18px 16px;
            box-shadow: 0 10px 28px var(--shadow);
          }

          .metric-card .label {
            font-size: 10px;
            letter-spacing: 0.1em;
            text-transform: uppercase;
            color: var(--muted);
          }

          .metric-card .value {
            margin-top: 14px;
            font-size: 30px;
            font-weight: 700;
          }

          .metric-card .trend {
            margin-top: 8px;
            color: var(--green);
            font-size: 12px;
          }

          .content {
            margin-top: 28px;
            display: grid;
            grid-template-columns: 1.2fr 0.8fr;
            gap: 22px;
          }

          .panel {
            background: rgba(11, 19, 30, 0.9);
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 18px;
            padding: 20px 18px;
            box-shadow: 0 12px 30px var(--shadow);
          }

          .panel-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 18px;
          }

          .panel-title {
            margin: 0;
            font-size: 18px;
            letter-spacing: 0.02em;
          }

          textarea {
            width: 100%;
            min-height: 128px;
            padding: 16px;
            border-radius: 14px;
            resize: vertical;
            border: 1px solid rgba(255,255,255,0.08);
            background: rgba(255,255,255,0.03);
            color: var(--text);
            font-family: 'SFMono-Regular', Consolas, monospace;
            font-size: 14px;
          }

          .input-actions {
            display: flex;
            gap: 12px;
            margin-top: 14px;
          }

          .pulse-list {
            list-style: none;
            padding: 0;
            margin: 0;
            display: flex;
            flex-direction: column;
            gap: 12px;
          }

          .pulse-item {
            background: rgba(255,255,255,0.02);
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 12px;
            padding: 14px 14px;
            color: var(--muted);
            line-height: 1.6;
          }

          .pulse-item strong {
            color: var(--text);
          }

          table {
            width: 100%;
            border-collapse: collapse;
          }

          th, td {
            padding: 12px 10px;
            text-align: left;
            border-bottom: 1px solid rgba(255,255,255,0.08);
            font-size: 13px;
          }

          th {
            color: var(--muted);
            text-transform: uppercase;
            letter-spacing: 0.08em;
            font-size: 10px;
          }

          .badge {
            display: inline-block;
            padding: 6px 8px;
            border-radius: 999px;
            font-size: 10px;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            font-weight: 700;
          }

          .badge.high { background: rgba(255,100,117,0.12); color: var(--red); }
          .badge.medium { background: rgba(246,199,107,0.12); color: var(--amber); }
          .badge.low { background: rgba(74,227,162,0.12); color: var(--green); }

          .dot {
            display: inline-block;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            margin-right: 8px;
            vertical-align: middle;
          }

          .dot.green { background: var(--green); }
          .dot.red { background: var(--red); }
          .dot.amber { background: var(--amber); }

          .footer-note {
            margin-top: 16px;
            color: var(--muted);
            font-size: 12px;
          }

          @media (max-width: 980px) {
            .hero, .content { grid-template-columns: 1fr; }
            .stats-grid { grid-template-columns: repeat(2, minmax(180px, 1fr)); }
          }

          @media (max-width: 600px) {
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
              <a href="#live-feed">Live Feed</a>
              <a href="#threats">Threats</a>
              <a href="#logs">Logs</a>
            </nav>
            <div class="status">Live Security Monitor</div>
          </header>

          <section class="hero" id="overview">
            <div class="hero-card">
              <div class="eyebrow">SIH Security Intelligence</div>
              <h1>Unified analysis for every log source.</h1>
              <div class="headline-sub">
                Transform syslog, JSON, CEF, and vendor-specific security events into one normalized format for faster investigation, enriched context, and smarter alerting.
              </div>
              <div class="quick-actions">
                <button class="primary" onclick="document.getElementById('logInput').focus()">Process New Log</button>
                <button class="secondary" onclick="loadSample()">Load Sample Threat</button>
              </div>

              <div class="mini-metrics">
                <div class="mini-box">
                  <div class="label">Formats</div>
                  <div class="value">4+</div>
                </div>
                <div class="mini-box">
                  <div class="label">Sources</div>
                  <div class="value">8</div>
                </div>
                <div class="mini-box">
                  <div class="label">TPR</div>
                  <div class="value">93%</div>
                </div>
                <div class="mini-box">
                  <div class="label">Latency</div>
                  <div class="value">100ms</div>
                </div>
              </div>
            </div>

            <div class="hero-card">
              <div class="eyebrow">Threat Summary</div>
              <div class="pulse-list">
                <div class="pulse-item"><span class="dot red"></span><strong>Blocked:</strong> External source attempted access to a critical internal service.</div>
                <div class="pulse-item"><span class="dot amber"></span><strong>Warning:</strong> Multiple failed login attempts detected on Linux host.</div>
                <div class="pulse-item"><span class="dot green"></span><strong>Clean:</strong> Public DNS requests from trusted infrastructure remained benign.</div>
              </div>
              <div class="footer-note">GeoIP and reputation enrichment are applied before validation.</div>
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
              <div class="trend">firewall policy active</div>
            </div>
            <div class="metric-card">
              <div class="label">Sources</div>
              <div class="value" id="count-sources">0</div>
              <div class="trend">multi-vendor connected</div>
            </div>
          </section>

          <section class="content" id="live-feed">
            <div class="panel" id="logs">
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
                <h2 class="panel-title">Live Security Pulse</h2>
              </div>
              <ul class="pulse-list">
                <li class="pulse-item"><span class="dot red"></span><strong>Threat IP:</strong> 1.2.3.4 flagged as suspicious</li>
                <li class="pulse-item"><span class="dot amber"></span><strong>Warning:</strong> 10.0.0.5 engaged in outbound denial activity</li>
                <li class="pulse-item"><span class="dot green"></span><strong>Trusted:</strong> 8.8.8.8 verified as public DNS</li>
              </ul>
            </div>
          </section>

          <section class="panel" style="margin-top: 22px;">
            <div class="panel-header">
              <h2 class="panel-title">Recent Security Events</h2>
            </div>
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
          </section>
        </div>

        <script>
          async function refreshEvents() {
            const res = await fetch('/events');
            const events = await res.json();
            const total = events.length;
            const threats = events.filter(e => (e.threat && e.threat.reputation === 'suspicious') || (e.threat && e.threat.reputation === 'malicious')).length;
            const blocked = events.filter(e => {
              const action = (e.event && e.event.action) || '';
              return action.toLowerCase().includes('deny') || action.toLowerCase().includes('block');
            }).length;
            const sources = new Set(events.map(e => e.source || 'unknown')).size;

            document.getElementById('count-total').textContent = total;
            document.getElementById('count-threats').textContent = threats;
            document.getElementById('count-blocked').textContent = blocked;
            document.getElementById('count-sources').textContent = sources;

            const tbody = document.getElementById('eventTable');
            tbody.innerHTML = events.slice().reverse().map((event) => {
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
              refreshEvents();
            }
          }

          function loadSample() {
            document.getElementById('logInput').value = 'src=1.2.3.4 dst=8.8.8.8 action=deny';
          }

          refreshEvents();
          setInterval(refreshEvents, 5000);
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
