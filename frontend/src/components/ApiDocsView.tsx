import React, { useState } from 'react';
import { BookOpen, Copy, Check, Terminal, ExternalLink, Code2 } from 'lucide-react';

export const ApiDocsView: React.FC = () => {
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const copyToClipboard = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const endpoints = [
    {
      id: 'get-health',
      method: 'GET',
      path: '/health',
      desc: 'Retrieves current framework health, uptime, total events, and registered sources.',
      curl: 'curl -s http://localhost:8000/health',
      response: `{
  "status": "ok",
  "service": "universal-log-framework",
  "uptime_seconds": 320,
  "total_events": 14,
  "sources": ["api", "firewall", "linux"]
}`,
    },
    {
      id: 'get-summary',
      method: 'GET',
      path: '/summary',
      desc: 'Returns security metrics including high-severity count, blocked events, suspicious IPs, and ML score.',
      curl: 'curl -s http://localhost:8000/summary',
      response: `{
  "total_events": 14,
  "high_severity": 4,
  "blocked_events": 6,
  "suspicious_ips": ["1.2.3.4", "185.220.101.5"],
  "ml_anomaly_score": 0.62,
  "ml_threat_label": "suspicious",
  "last_updated": "2026-08-30T17:40:00Z"
}`,
    },
    {
      id: 'post-logs',
      method: 'POST',
      path: '/logs',
      desc: 'Ingests, detects format, normalizes, enriches with GeoIP & threat intel, scores anomaly, and stores event.',
      curl: `curl -X POST http://localhost:8000/logs \\
  -H "Content-Type: application/json" \\
  -d '{"log":"CEF:0|Palo Alto|PAN-OS|11.0|THREAT|C2|9|src=1.2.3.4 dst=10.0.0.1 msg=c2-beacon action=deny"}'`,
      response: `{
  "source": "api",
  "event": {
    "action": "deny",
    "severity": "9",
    "message": "c2-beacon"
  },
  "network": {
    "source_ip": "1.2.3.4",
    "destination_ip": "10.0.0.1"
  },
  "enrichment": {
    "country": "CN",
    "city": "Hangzhou"
  },
  "threat": {
    "reputation": "suspicious",
    "category": "botnet"
  }
}`,
    },
    {
      id: 'post-batch-logs',
      method: 'POST',
      path: '/api/logs/batch',
      desc: 'High-throughput batch ingestion endpoint to process an array of heterogeneous logs simultaneously.',
      curl: `curl -X POST http://localhost:8000/api/logs/batch \\
  -H "Content-Type: application/json" \\
  -d '{"logs":["src=10.0.0.5 dst=8.8.8.8 action=deny", "Aug 30 12:00:00 web-01 sshd: Failed password for root"]}'`,
      response: `[
  { "network": { "source_ip": "10.0.0.5", "destination_ip": "8.8.8.8" }, "event": { "action": "deny" } },
  { "source": "linux", "event": { "action": "fail", "severity": "medium" } }
]`,
    },
    {
      id: 'get-events',
      method: 'GET',
      path: '/events',
      desc: 'Fetches the complete array of all in-memory canonical normalized security events.',
      curl: 'curl -s http://localhost:8000/events',
      response: `[
  {
    "timestamp": "2026-08-30T10:32:00Z",
    "source": "firewall",
    "event": { "action": "blocked", "severity": "high" },
    "network": { "source_ip": "192.168.1.10", "destination_ip": "8.8.8.8" },
    "enrichment": { "country": "IN" },
    "threat": { "reputation": "unknown" }
  }
]`,
    },
    {
      id: 'get-ml-insights',
      method: 'GET',
      path: '/api/ml/insights',
      desc: 'Retrieves the Random Forest anomaly classification model score and per-event decision breakdown.',
      curl: 'curl -s http://localhost:8000/api/ml/insights',
      response: `{
  "anomaly_score": 0.58,
  "threat_label": "suspicious",
  "total_evaluated": 14,
  "model": "random-forest-anomaly-model",
  "details": [
    { "source": "api", "score": 0.92, "label": "critical", "severity": "high" }
  ]
}`,
    },
    {
      id: 'post-clear',
      method: 'POST',
      path: '/api/events/clear',
      desc: 'Clears all in-memory events from the local buffer (useful for test resets).',
      curl: 'curl -X POST http://localhost:8000/api/events/clear',
      response: `{
  "message": "Event store cleared",
  "count": 14
}`,
    },
  ];

  return (
    <div className="api-docs-container glass-panel fade-in">
      <div className="card-header-flex">
        <div>
          <div className="badge badge-purple mb-8">
            <BookOpen size={12} /> RESTful API Specification
          </div>
          <h2 className="section-title">Universal Log Framework API Endpoints</h2>
          <p className="card-subtitle">
            Integrate downstream SIEMs, log forwarders (FluentBit, Logstash), and SOC automation tools.
          </p>
        </div>

        <a
          href="http://localhost:8000/docs"
          target="_blank"
          rel="noreferrer"
          className="btn btn-primary btn-sm"
        >
          <ExternalLink size={14} />
          <span>Interactive Swagger UI</span>
        </a>
      </div>

      <div className="endpoints-list">
        {endpoints.map((ep) => {
          const isGet = ep.method === 'GET';
          return (
            <div key={ep.id} className="endpoint-card glass-panel">
              <div className="endpoint-header">
                <div className="endpoint-signature">
                  <span className={`method-badge ${isGet ? 'get' : 'post'}`}>
                    {ep.method}
                  </span>
                  <span className="endpoint-path mono">{ep.path}</span>
                </div>
                <span className="endpoint-desc">{ep.desc}</span>
              </div>

              <div className="endpoint-code-grid">
                {/* Request cURL */}
                <div className="code-block-col">
                  <div className="code-header">
                    <div className="code-title">
                      <Terminal size={12} />
                      <span>cURL Request</span>
                    </div>
                    <button
                      onClick={() => copyToClipboard(ep.id + '-curl', ep.curl)}
                      className="btn-copy-code"
                    >
                      {copiedId === ep.id + '-curl' ? <Check size={12} /> : <Copy size={12} />}
                      <span>{copiedId === ep.id + '-curl' ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                  <pre className="code-pre mono">{ep.curl}</pre>
                </div>

                {/* Response JSON */}
                <div className="code-block-col">
                  <div className="code-header">
                    <div className="code-title">
                      <Code2 size={12} />
                      <span>Response Schema</span>
                    </div>
                    <button
                      onClick={() => copyToClipboard(ep.id + '-json', ep.response)}
                      className="btn-copy-code"
                    >
                      {copiedId === ep.id + '-json' ? <Check size={12} /> : <Copy size={12} />}
                      <span>{copiedId === ep.id + '-json' ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                  <pre className="code-pre mono">{ep.response}</pre>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
