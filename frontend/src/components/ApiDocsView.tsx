import React, { useState } from 'react';
import {
  Copy,
  Check,
  Terminal,
  ExternalLink,
  Code2,
  Play,
} from 'lucide-react';
import { getApiBase } from '../api';

export const ApiDocsView: React.FC = () => {
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [activeLang, setActiveLang] = useState<'curl' | 'python' | 'node'>('curl');
  const [activeCategory, setActiveCategory] = useState<'all' | 'ingest' | 'telemetry' | 'ml' | 'health'>('all');
  const [liveTestResponse, setLiveTestResponse] = useState<{ [key: string]: { loading: boolean; data?: string; status?: number; time?: number } }>({});

  const apiBase = getApiBase() || (typeof window !== 'undefined' ? window.location.origin : 'http://localhost:8000');

  const copyToClipboard = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleTestEndpoint = async (epId: string, path: string, method: string, body?: string) => {
    setLiveTestResponse((prev) => ({ ...prev, [epId]: { loading: true } }));
    const startTime = performance.now();

    try {
      const res = await fetch(`${apiBase}${path}`, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: method === 'POST' && body ? body : undefined,
      });
      const endTime = performance.now();
      const data = await res.json();
      setLiveTestResponse((prev) => ({
        ...prev,
        [epId]: {
          loading: false,
          data: JSON.stringify(data, null, 2),
          status: res.status,
          time: Math.round(endTime - startTime),
        },
      }));
    } catch (err: unknown) {
      const endTime = performance.now();
      setLiveTestResponse((prev) => ({
        ...prev,
        [epId]: {
          loading: false,
          data: JSON.stringify({ error: err instanceof Error ? err.message : 'Network request failed' }, null, 2),
          status: 500,
          time: Math.round(endTime - startTime),
        },
      }));
    }
  };

  const endpoints = [
    {
      id: 'post-logs',
      category: 'ingest',
      method: 'POST',
      path: '/logs',
      title: 'Normalize Single Log Payload',
      desc: 'Ingests a raw heterogeneous security log (Syslog, CEF, LEEF, JSON, Key-Value). Detects format automatically, normalizes into canonical OCSF schema, enriches with GeoIP & threat intelligence, and runs Random Forest anomaly classification.',
      headers: [{ name: 'Content-Type', type: 'string', required: true, desc: 'application/json' }],
      bodyParams: [{ name: 'log', type: 'string', required: true, desc: 'Raw string telemetry payload from firewall, auth, or endpoint' }],
      requestBody: '{\n  "log": "CEF:0|Palo Alto Networks|PAN-OS|11.0|THREAT|C2-Beacon|9|src=1.2.3.4 dst=10.5.2.4 msg=c2-beacon action=deny country=CN"\n}',
      curl: `curl -X POST "${apiBase}/logs" \\\n  -H "Content-Type: application/json" \\\n  -d '{"log":"src=1.2.3.4 dst=10.5.2.4 action=deny country=CN"}'`,
      python: `import requests\n\nurl = "${apiBase}/logs"\npayload = {"log": "src=1.2.3.4 dst=10.5.2.4 action=deny country=CN"}\nresponse = requests.post(url, json=payload)\nprint(response.json())`,
      node: `const res = await fetch("${apiBase}/logs", {\n  method: "POST",\n  headers: { "Content-Type": "application/json" },\n  body: JSON.stringify({ log: "src=1.2.3.4 dst=10.5.2.4 action=deny" })\n});\nconst data = await res.json();\nconsole.log(data);`,
      response: `{\n  "timestamp": "2026-08-31T11:00:00Z",\n  "source": "cef",\n  "event": {\n    "action": "deny",\n    "severity": "critical",\n    "message": "c2-beacon"\n  },\n  "network": {\n    "source_ip": "1.2.3.4",\n    "destination_ip": "10.5.2.4",\n    "source_port": "443",\n    "destination_port": "58920"\n  },\n  "enrichment": {\n    "country": "CN",\n    "city": "Hangzhou",\n    "geo_risk": 0.95\n  },\n  "threat": {\n    "reputation": "suspicious",\n    "category": "botnet"\n  }\n}`,
    },
    {
      id: 'post-batch-logs',
      category: 'ingest',
      method: 'POST',
      path: '/api/logs/batch',
      title: 'High-Throughput Batch Ingestion',
      desc: 'Bulk normalization endpoint accepting arrays of heterogeneous log strings. Processes multi-vendor telemetry with zero-loss parallel parsing.',
      headers: [{ name: 'Content-Type', type: 'string', required: true, desc: 'application/json' }],
      bodyParams: [{ name: 'logs', type: 'Array<string>', required: true, desc: 'Array of raw string logs (up to 1,000 events/batch)' }],
      requestBody: '{\n  "logs": [\n    "src=10.0.0.5 dst=8.8.8.8 action=deny",\n    "Aug 31 10:45:00 web-01 sshd[4192]: Failed password for admin from 192.168.1.10 port 22"\n  ]\n}',
      curl: `curl -X POST "${apiBase}/api/logs/batch" \\\n  -H "Content-Type: application/json" \\\n  -d '{"logs":["src=10.0.0.5 dst=8.8.8.8 action=deny"]}'`,
      python: `import requests\n\nurl = "${apiBase}/api/logs/batch"\npayload = {"logs": ["src=10.0.0.5 dst=8.8.8.8 action=deny"]}\nresponse = requests.post(url, json=payload)\nprint(response.json())`,
      node: `const res = await fetch("${apiBase}/api/logs/batch", {\n  method: "POST",\n  headers: { "Content-Type": "application/json" },\n  body: JSON.stringify({ logs: ["src=10.0.0.5 dst=8.8.8.8 action=deny"] })\n});\nconsole.log(await res.json());`,
      response: `[\n  {\n    "timestamp": "2026-08-31T11:00:00Z",\n    "source": "firewall",\n    "network": { "source_ip": "10.0.0.5", "destination_ip": "8.8.8.8" },\n    "event": { "action": "deny", "severity": "low" }\n  }\n]`,
    },
    {
      id: 'get-events',
      category: 'telemetry',
      method: 'GET',
      path: '/events',
      title: 'Query Normalized Canonical Events',
      desc: 'Retrieves all unified canonical security events from the active in-memory buffer. Each event adheres to standard OCSF/Elastic schema format.',
      headers: [],
      bodyParams: [],
      curl: `curl -s "${apiBase}/events"`,
      python: `import requests\n\nresponse = requests.get("${apiBase}/events")\nevents = response.json()\nprint(f"Retrieved {len(events)} events")`,
      node: `const res = await fetch("${apiBase}/events");\nconst events = await res.json();\nconsole.log(events);`,
      response: `[\n  {\n    "timestamp": "2026-08-31T10:32:00Z",\n    "source": "firewall",\n    "event": { "action": "blocked", "severity": "high" },\n    "network": { "source_ip": "192.168.1.10", "destination_ip": "8.8.8.8" },\n    "enrichment": { "country": "IN", "geo_risk": 0.15 },\n    "threat": { "reputation": "unknown" }\n  }\n]`,
    },
    {
      id: 'get-overview',
      category: 'telemetry',
      method: 'GET',
      path: '/api/overview',
      title: 'SOC Analytics Dashboard Overview',
      desc: 'Aggregates global telemetry, correlated alerts, scored priority incidents, and monitored asset health states for dashboard visualization.',
      headers: [],
      bodyParams: [],
      curl: `curl -s "${apiBase}/api/overview"`,
      python: `import requests\n\noverview = requests.get("${apiBase}/api/overview").json()\nprint(overview["summary"])`,
      node: `const res = await fetch("${apiBase}/api/overview");\nconst overview = await res.json();\nconsole.log(overview);`,
      response: `{\n  "summary": {\n    "total_events": 14,\n    "high_severity": 4,\n    "blocked_events": 6,\n    "suspicious_ips": ["1.2.3.4", "185.220.101.5"]\n  },\n  "alerts": [ { "title": "C2 beaconing detected", "severity": "high" } ],\n  "incidents": [ { "title": "Malicious outbound connection", "score": 92 } ]\n}`,
    },
    {
      id: 'get-ml-insights',
      category: 'ml',
      method: 'GET',
      path: '/api/ml/insights',
      title: 'ML Random Forest Threat Scoring',
      desc: 'Evaluates the 7-dimensional feature matrix across all ingested events and returns probabilistic anomaly classification scores and risk rankings.',
      headers: [],
      bodyParams: [],
      curl: `curl -s "${apiBase}/api/ml/insights"`,
      python: `import requests\n\ninsights = requests.get("${apiBase}/api/ml/insights").json()\nprint("Anomaly Score:", insights["anomaly_score"])\nprint("Threat Label:", insights["threat_label"])`,
      node: `const res = await fetch("${apiBase}/api/ml/insights");\nconst ml = await res.json();\nconsole.log(ml);`,
      response: `{\n  "model": "RandomForestClassifier (100 Estimators)",\n  "anomaly_score": 0.72,\n  "threat_label": "suspicious",\n  "total_evaluated": 14,\n  "details": [\n    { "source": "api", "score": 0.94, "label": "suspicious", "severity": "critical" }\n  ]\n}`,
    },
    {
      id: 'get-health',
      category: 'health',
      method: 'GET',
      path: '/health',
      title: 'Core Engine Health & Telemetry',
      desc: 'Health check endpoint verifying server operational status, uptime counters, event buffer volume, and registered multi-vendor log sources.',
      headers: [],
      bodyParams: [],
      curl: `curl -s "${apiBase}/health"`,
      python: `import requests\n\nhealth = requests.get("${apiBase}/health").json()\nprint("Engine Status:", health["status"])`,
      node: `const res = await fetch("${apiBase}/health");\nconst health = await res.json();\nconsole.log(health);`,
      response: `{\n  "status": "ok",\n  "service": "universal-log-framework",\n  "uptime_seconds": 320,\n  "total_events": 14,\n  "sources": ["api", "firewall", "linux", "syslog"]\n}`,
    },
    {
      id: 'get-summary',
      category: 'health',
      method: 'GET',
      path: '/summary',
      title: 'Quick KPI Security Summary',
      desc: 'Lightweight KPI metric endpoint returning total events, blocked counts, severity counts, and suspicious IOC addresses.',
      headers: [],
      bodyParams: [],
      curl: `curl -s "${apiBase}/summary"`,
      python: `import requests\n\nsummary = requests.get("${apiBase}/summary").json()\nprint("Blocked Events:", summary["blocked_events"])`,
      node: `const res = await fetch("${apiBase}/summary");\nconsole.log(await res.json());`,
      response: `{\n  "total_events": 14,\n  "high_severity": 4,\n  "blocked_events": 6,\n  "suspicious_ips": ["1.2.3.4", "185.220.101.5"],\n  "ml_anomaly_score": 0.72,\n  "ml_threat_label": "suspicious"\n}`,
    },
  ];

  const filteredEndpoints = endpoints.filter((ep) => {
    if (activeCategory === 'all') return true;
    return ep.category === activeCategory;
  });

  return (
    <div className="api-docs-container glass-panel fade-in">
      {/* Top Banner */}
      <div className="api-docs-hero">
        <div className="api-docs-hero-left">
          <div className="badge-row" style={{ display: 'flex', gap: '8px', marginBottom: '8px' }}>
            <span className="badge badge-purple">OpenAPI 3.1 &amp; Swagger Compliant</span>
            <span className="badge badge-cyan">RESTful JSON Specification</span>
          </div>
          <h2 className="api-hero-title">Developer API Reference &amp; Integration Hub</h2>
          <p className="api-hero-subtitle">
            Programmatically stream raw security telemetry, trigger canonical normalization pipelines, fetch enriched IOCs, and query Random Forest ML classifications.
          </p>
        </div>

        <div className="api-docs-hero-right">
          <div className="api-base-url-card">
            <span className="api-base-label">Active Base URL:</span>
            <span className="api-base-val mono">{apiBase}</span>
          </div>
          <a
            href={`${apiBase}/docs`}
            target="_blank"
            rel="noreferrer"
            className="btn btn-primary btn-sm"
          >
            <ExternalLink size={15} />
            <span>Interactive Swagger UI</span>
          </a>
        </div>
      </div>

      {/* Category Navigation Bar & Language Switcher */}
      <div className="api-nav-toolbar">
        <div className="api-category-tabs">
          <button
            onClick={() => setActiveCategory('all')}
            className={`api-category-btn ${activeCategory === 'all' ? 'active' : ''}`}
          >
            All Endpoints ({endpoints.length})
          </button>
          <button
            onClick={() => setActiveCategory('ingest')}
            className={`api-category-btn ${activeCategory === 'ingest' ? 'active' : ''}`}
          >
            Log Ingestion (2)
          </button>
          <button
            onClick={() => setActiveCategory('telemetry')}
            className={`api-category-btn ${activeCategory === 'telemetry' ? 'active' : ''}`}
          >
            SIEM Telemetry (2)
          </button>
          <button
            onClick={() => setActiveCategory('ml')}
            className={`api-category-btn ${activeCategory === 'ml' ? 'active' : ''}`}
          >
            ML Engine (1)
          </button>
          <button
            onClick={() => setActiveCategory('health')}
            className={`api-category-btn ${activeCategory === 'health' ? 'active' : ''}`}
          >
            Health &amp; Summary (2)
          </button>
        </div>

        {/* Code Sample Language Selector */}
        <div className="api-lang-selector">
          <span className="lang-lbl">Sample:</span>
          <button
            onClick={() => setActiveLang('curl')}
            className={`lang-tab-btn ${activeLang === 'curl' ? 'active' : ''}`}
          >
            cURL
          </button>
          <button
            onClick={() => setActiveLang('python')}
            className={`lang-tab-btn ${activeLang === 'python' ? 'active' : ''}`}
          >
            Python
          </button>
          <button
            onClick={() => setActiveLang('node')}
            className={`lang-tab-btn ${activeLang === 'node' ? 'active' : ''}`}
          >
            Node.js
          </button>
        </div>
      </div>

      {/* Endpoints Detailed Cards List */}
      <div className="endpoints-cards-list">
        {filteredEndpoints.map((ep) => {
          const isGet = ep.method === 'GET';
          const codeSnippet = activeLang === 'curl' ? ep.curl : activeLang === 'python' ? ep.python : ep.node;
          const liveRes = liveTestResponse[ep.id];

          return (
            <div key={ep.id} className="endpoint-reference-card glass-panel">
              {/* Endpoint Left Column: Documentation & Parameter Table */}
              <div className="endpoint-doc-col">
                <div className="endpoint-header-row">
                  <span className={`method-badge ${isGet ? 'get' : 'post'}`}>
                    {ep.method}
                  </span>
                  <span className="endpoint-path-text mono">{ep.path}</span>
                </div>

                <h3 className="endpoint-heading">{ep.title}</h3>
                <p className="endpoint-description">{ep.desc}</p>

                {/* Headers Table */}
                {ep.headers.length > 0 && (
                  <div className="endpoint-spec-section">
                    <span className="spec-section-title">REQUEST HEADERS</span>
                    <div className="spec-table-wrap">
                      <table className="spec-table">
                        <tbody>
                          {ep.headers.map((h) => (
                            <tr key={h.name}>
                              <td className="mono spec-param-name">{h.name}</td>
                              <td className="spec-param-type mono">{h.type}</td>
                              <td className="spec-param-desc">{h.desc}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {/* Request Body Parameters */}
                {ep.bodyParams.length > 0 && (
                  <div className="endpoint-spec-section">
                    <span className="spec-section-title">REQUEST BODY SCHEMA</span>
                    <div className="spec-table-wrap">
                      <table className="spec-table">
                        <tbody>
                          {ep.bodyParams.map((p) => (
                            <tr key={p.name}>
                              <td className="mono spec-param-name">{p.name}</td>
                              <td className="spec-param-type mono">{p.type}</td>
                              <td className="spec-param-desc">{p.desc}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {/* Interactive Try-It Live Button */}
                <div className="endpoint-try-actions">
                  <button
                    onClick={() => handleTestEndpoint(ep.id, ep.path, ep.method, ep.requestBody)}
                    disabled={liveRes?.loading}
                    className="btn btn-primary btn-sm btn-try-live"
                  >
                    <Play size={13} />
                    <span>{liveRes?.loading ? 'Executing Live Request...' : 'Send Test Request'}</span>
                  </button>
                  {liveRes?.status && (
                    <span className={`badge ${liveRes.status === 200 ? 'badge-low' : 'badge-critical'}`}>
                      HTTP {liveRes.status} ({liveRes.time}ms)
                    </span>
                  )}
                </div>
              </div>

              {/* Endpoint Right Column: Interactive Code Samples & Live Response */}
              <div className="endpoint-code-col">
                {/* Code Sample Box */}
                <div className="terminal-code-box">
                  <div className="terminal-code-header">
                    <div className="terminal-code-title">
                      <Terminal size={14} className="text-cyan" />
                      <span className="mono">{activeLang.toUpperCase()} Request</span>
                    </div>
                    <button
                      onClick={() => copyToClipboard(ep.id + '-code', codeSnippet)}
                      className="btn-copy-code"
                      title="Copy Code"
                    >
                      {copiedId === ep.id + '-code' ? <Check size={13} className="text-emerald" /> : <Copy size={13} />}
                      <span>{copiedId === ep.id + '-code' ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                  <pre className="terminal-pre-code mono">{codeSnippet}</pre>
                </div>

                {/* Expected or Live Response Box */}
                <div className="terminal-code-box">
                  <div className="terminal-code-header">
                    <div className="terminal-code-title">
                      <Code2 size={14} className="text-coral" />
                      <span className="mono">{liveRes?.data ? 'Live Server Response' : 'Response Schema (200 OK)'}</span>
                    </div>
                    <button
                      onClick={() => copyToClipboard(ep.id + '-res', liveRes?.data || ep.response)}
                      className="btn-copy-code"
                      title="Copy JSON Response"
                    >
                      {copiedId === ep.id + '-res' ? <Check size={13} className="text-emerald" /> : <Copy size={13} />}
                      <span>{copiedId === ep.id + '-res' ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                  <pre className="terminal-pre-code mono">
                    {liveRes?.data || ep.response}
                  </pre>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
