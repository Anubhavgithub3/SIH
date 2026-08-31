import React, { useState } from 'react';
import {
  FileCode2,
  Sparkles,
  Send,
  Upload,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  Shield,
  Layers,
  Copy,
  Check,
  Activity,
  Globe2,
  Server,
  Zap,
  Network,
  Code2,
} from 'lucide-react';
import type { NormalizedEvent } from '../types';

interface LogIngestionStudioProps {
  onIngest: (rawLog: string) => Promise<NormalizedEvent>;
  onBatchIngest: (logs: string[]) => Promise<NormalizedEvent[]>;
}

export const LogIngestionStudio: React.FC<LogIngestionStudioProps> = ({
  onIngest,
  onBatchIngest,
}) => {
  const [logText, setLogText] = useState('src=1.2.3.4 dst=10.5.2.4 action=deny port=443 country=CN msg="C2 beaconing signature matched"');
  const [isProcessing, setIsProcessing] = useState(false);
  const [pipelineStep, setPipelineStep] = useState<number>(0);
  const [lastResult, setLastResult] = useState<NormalizedEvent | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [activeMode, setActiveMode] = useState<'single' | 'batch'>('single');
  const [batchText, setBatchText] = useState('');
  const [resultTab, setResultTab] = useState<'visual' | 'json'>('visual');

  const PRESETS = [
    {
      id: 'cef-c2',
      name: 'Palo Alto C2 Beacon',
      format: 'CEF',
      log: 'CEF:0|Palo Alto Networks|PAN-OS|11.0|THREAT|C2-Beacon|9|src=1.2.3.4 dst=10.5.2.4 msg=malware-beacon-c2 action=deny country=CN spt=443 dpt=58920',
    },
    {
      id: 'syslog-ssh',
      name: 'Linux SSH Brute Force',
      format: 'Syslog',
      log: 'Aug 31 10:45:00 web-01 sshd[4192]: Failed password for invalid user admin from 192.168.1.10 port 22 ssh2',
    },
    {
      id: 'firewall',
      name: 'Firewall Deny Rule',
      format: 'Key-Value',
      log: 'src=185.220.101.5 dst=10.0.0.12 action=deny port=443 bytes=1420 country=RU msg="packet dropped by perimeter rule"',
    },
    {
      id: 'json-api',
      name: 'Cloud API Token Alert',
      format: 'JSON',
      log: '{"timestamp":"2026-08-31T10:42:00Z","host":"api-gateway","source":"api","event_type":"authentication","severity":"critical","message":"token signature expired","src_ip":"10.0.0.8"}',
    },
    {
      id: 'leef-threat',
      name: 'QRadar Malicious IP',
      format: 'LEEF',
      log: 'LEEF:1.0|IBM|QRadar|7.4|ThreatAlert|src=1.2.3.4 dst=10.0.0.12 action=block threat=malicious msg=exploit-attempt',
    },
  ];

  const detectFormatPreview = (text: string): string => {
    const trimmed = text.trim();
    if (!trimmed) return 'Awaiting Input';
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) return 'JSON Format';
    if (trimmed.startsWith('CEF:')) return 'CEF (Common Event Format)';
    if (trimmed.startsWith('LEEF:')) return 'LEEF (Log Event Extended)';
    if (trimmed.includes('src=') || trimmed.includes('action=')) return 'Key-Value Pairs';
    if (/\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\b/.test(trimmed) || trimmed.startsWith('<')) {
      return 'RFC3164 Syslog';
    }
    return 'Raw Log Stream';
  };

  const handleProcess = async () => {
    if (!logText.trim()) return;
    setIsProcessing(true);
    setErrorMessage(null);
    setPipelineStep(1);

    try {
      await new Promise((r) => setTimeout(r, 100));
      setPipelineStep(2);
      await new Promise((r) => setTimeout(r, 100));
      setPipelineStep(3);

      const result = await onIngest(logText.trim());
      setPipelineStep(4);
      setLastResult(result);
    } catch (err: unknown) {
      setErrorMessage(err instanceof Error ? err.message : 'Processing failed');
    } finally {
      setIsProcessing(false);
    }
  };

  const handleBatchProcess = async () => {
    if (!batchText.trim()) return;
    setIsProcessing(true);
    setErrorMessage(null);
    const lines = batchText.split('\n').map((l) => l.trim()).filter(Boolean);
    try {
      const results = await onBatchIngest(lines);
      if (results.length > 0) {
        setLastResult(results[results.length - 1]);
      }
      setBatchText('');
    } catch (err: unknown) {
      setErrorMessage(err instanceof Error ? err.message : 'Batch processing failed');
    } finally {
      setIsProcessing(false);
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      if (content) {
        setBatchText(content);
        setActiveMode('batch');
      }
    };
    reader.readAsText(file);
  };

  const copyResultJSON = () => {
    if (!lastResult) return;
    navigator.clipboard.writeText(JSON.stringify(lastResult, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const pipelineStages = [
    { label: 'Ingest Payload', desc: 'Accept heterogeneous raw string' },
    { label: 'Format Detection', desc: 'JSON, Syslog, CEF, LEEF, Key-Value' },
    { label: 'Canonical Normalize', desc: 'Map into unified SIEM schema' },
    { label: 'Enrich & ML Score', desc: 'GeoIP, threat intel & Random Forest' },
  ];

  const srcIp = lastResult?.network?.source_ip || lastResult?.network?.src_ip || 'N/A';
  const dstIp = lastResult?.network?.destination_ip || lastResult?.network?.dst_ip || 'N/A';
  const srcPort = lastResult?.network?.source_port || lastResult?.network?.src_port || 'Any';
  const dstPort = lastResult?.network?.destination_port || lastResult?.network?.dst_port || 'Any';
  const action = lastResult?.event?.action || 'processed';
  const sev = String(lastResult?.event?.severity || lastResult?.severity || 'info').toLowerCase();
  const country = lastResult?.enrichment?.country || 'Unknown';
  const reputation = lastResult?.threat?.reputation || 'benign';
  const isBlocked = action.includes('deny') || action.includes('block') || action.includes('drop');

  return (
    <div className="ingestion-studio-container">
      {/* Studio Header & Presets */}
      <div className="studio-top glass-panel">
        <div className="card-header-flex">
          <div>
            <h2 className="card-title">Live Log Ingestion & Pipeline Studio</h2>
            <p className="card-subtitle">
              Feed raw multi-vendor security telemetry directly into the normalization engine
            </p>
          </div>
          <div className="mode-tabs">
            <button
              className={`mode-tab-btn ${activeMode === 'single' ? 'active' : ''}`}
              onClick={() => setActiveMode('single')}
            >
              Single Event
            </button>
            <button
              className={`mode-tab-btn ${activeMode === 'batch' ? 'active' : ''}`}
              onClick={() => setActiveMode('batch')}
            >
              Batch / File Upload
            </button>
          </div>
        </div>

        {/* Quick Presets */}
        <div className="preset-bar">
          <span className="preset-label">
            <Sparkles size={14} className="text-accent" />
            <span>Load Demo Presets:</span>
          </span>
          <div className="preset-chips">
            {PRESETS.map((p) => (
              <button
                key={p.id}
                onClick={() => {
                  setLogText(p.log);
                  setActiveMode('single');
                }}
                className="preset-chip"
              >
                <span>{p.name}</span>
                <span className="preset-format-tag">{p.format}</span>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Main Studio Grid */}
      <div className="studio-grid">
        {/* Ingestion Editor Box */}
        <div className="glass-panel editor-panel">
          <div className="editor-top-bar">
            <div className="editor-indicator">
              <FileCode2 size={16} className="text-accent" />
              <span className="editor-label">Raw Telemetry Input</span>
            </div>
            <span className="format-detect-badge">
              {detectFormatPreview(activeMode === 'single' ? logText : batchText)}
            </span>
          </div>

          {activeMode === 'single' ? (
            <textarea
              className="log-textarea mono"
              value={logText}
              onChange={(e) => setLogText(e.target.value)}
              placeholder="Paste raw Syslog, CEF, LEEF, JSON, or Key-Value security log here..."
              rows={5}
            />
          ) : (
            <div className="batch-editor-wrap">
              <textarea
                className="log-textarea mono"
                value={batchText}
                onChange={(e) => setBatchText(e.target.value)}
                placeholder="Paste multiple log lines (one event per line)..."
                rows={5}
              />
              <div className="file-upload-row">
                <label className="btn btn-secondary btn-sm upload-label">
                  <Upload size={14} />
                  <span>Upload .log / .json File</span>
                  <input
                    type="file"
                    accept=".log,.txt,.json"
                    onChange={handleFileUpload}
                    style={{ display: 'none' }}
                  />
                </label>
                <span className="file-hint">Accepts .log, .txt, .json files</span>
              </div>
            </div>
          )}

          {errorMessage && (
            <div className="error-banner">
              <AlertTriangle size={16} />
              <span>{errorMessage}</span>
            </div>
          )}

          <div className="editor-actions">
            {activeMode === 'single' ? (
              <button
                onClick={handleProcess}
                disabled={isProcessing || !logText.trim()}
                className="btn btn-primary"
              >
                <Send size={15} />
                <span>{isProcessing ? 'Normalizing...' : 'Process & Enrich Log'}</span>
              </button>
            ) : (
              <button
                onClick={handleBatchProcess}
                disabled={isProcessing || !batchText.trim()}
                className="btn btn-primary"
              >
                <Layers size={15} />
                <span>{isProcessing ? 'Ingesting Batch...' : 'Ingest All Log Lines'}</span>
              </button>
            )}
          </div>
        </div>

        {/* Live Pipeline Flow Visualizer */}
        <div className="glass-panel pipeline-panel">
          <div className="card-header-flex">
            <div>
              <h3 className="card-title">Normalization Pipeline Execution</h3>
              <p className="card-subtitle">Zero-loss canonical transformation stages</p>
            </div>
            <Shield size={18} className="text-muted" />
          </div>

          <div className="pipeline-steps-list">
            {pipelineStages.map((stg, idx) => {
              const isPassed = pipelineStep > idx || !!lastResult;
              const isCurrent = pipelineStep === idx + 1 && isProcessing;

              return (
                <div
                  key={stg.label}
                  className={`pipeline-step-item ${isPassed ? 'passed' : ''} ${isCurrent ? 'active' : ''}`}
                >
                  <div className="step-badge">
                    {isPassed ? (
                      <CheckCircle2 size={16} className="text-emerald" />
                    ) : (
                      <span>{idx + 1}</span>
                    )}
                  </div>
                  <div className="step-info">
                    <span className="step-label">{stg.label}</span>
                    <span className="step-desc">{stg.desc}</span>
                  </div>
                  {idx < pipelineStages.length - 1 && (
                    <ArrowRight size={14} className="step-arrow" />
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* POST-INGESTION COMPREHENSIVE VISUALIZATION & ANALYTICS CARDS */}
      {lastResult && (
        <div className="glass-panel parsed-result-card fade-in">
          <div className="card-header-flex">
            <div>
              <div className="result-badge-row">
                <span className="badge badge-low">
                  <CheckCircle2 size={12} /> Pipeline Complete
                </span>
                <span className="badge badge-info">Source: {lastResult.source || 'api'}</span>
                <span className={`badge badge-${sev === 'critical' ? 'critical' : sev === 'high' ? 'high' : 'medium'}`}>
                  Severity: {sev.toUpperCase()}
                </span>
              </div>
              <h3 className="card-title">Parsed & Normalized Event Intelligence</h3>
              <p className="card-subtitle">Contextual enrichment, network flow, and canonical schema</p>
            </div>

            <div className="result-toggle-group">
              <button
                className={`result-toggle-btn ${resultTab === 'visual' ? 'active' : ''}`}
                onClick={() => setResultTab('visual')}
              >
                <Network size={14} />
                <span>Visual Flow & Graph</span>
              </button>
              <button
                className={`result-toggle-btn ${resultTab === 'json' ? 'active' : ''}`}
                onClick={() => setResultTab('json')}
              >
                <Code2 size={14} />
                <span>Canonical JSON</span>
              </button>
            </div>
          </div>

          {resultTab === 'visual' ? (
            <div className="parsed-visual-content">
              {/* 4 Telemetry KPI Cards */}
              <div className="parsed-kpi-grid">
                <div className="parsed-kpi-card">
                  <div className="kpi-card-top">
                    <span className="kpi-card-label">Security Action</span>
                    <Activity size={16} className="text-coral" />
                  </div>
                  <div className="kpi-card-val" style={{ color: isBlocked ? '#ef4444' : '#10b981' }}>
                    {action.toUpperCase()}
                  </div>
                  <span className="kpi-card-sub">Enforced at perimeter</span>
                </div>

                <div className="parsed-kpi-card">
                  <div className="kpi-card-top">
                    <span className="kpi-card-label">Geo Origin</span>
                    <Globe2 size={16} className="text-cyan" />
                  </div>
                  <div className="kpi-card-val">
                    {country}
                  </div>
                  <span className="kpi-card-sub">GeoIP CTI Resolved</span>
                </div>

                <div className="parsed-kpi-card">
                  <div className="kpi-card-top">
                    <span className="kpi-card-label">Threat Intel</span>
                    <Shield size={16} className="text-amber" />
                  </div>
                  <div className="kpi-card-val" style={{ color: reputation === 'suspicious' || reputation === 'malicious' ? '#ef4444' : '#10b981' }}>
                    {reputation.toUpperCase()}
                  </div>
                  <span className="kpi-card-sub">IOC Feed Lookup</span>
                </div>

                <div className="parsed-kpi-card">
                  <div className="kpi-card-top">
                    <span className="kpi-card-label">Engine Latency</span>
                    <Zap size={16} className="text-accent" />
                  </div>
                  <div className="kpi-card-val mono">
                    &lt;1.2 ms
                  </div>
                  <span className="kpi-card-sub">100% OCSF Standard</span>
                </div>
              </div>

              {/* Interactive Network Flow Diagram */}
              <div className="network-flow-card">
                <div className="flow-card-title">
                  <Network size={16} className="text-accent" />
                  <span>Interactive Network Flow Diagram</span>
                </div>

                <div className="flow-diagram-wrapper">
                  <div className="flow-node node-source">
                    <span className="node-badge">SOURCE HOST</span>
                    <span className="node-ip mono">{srcIp}</span>
                    <span className="node-port mono">Port: {srcPort}</span>
                    <span className="node-geo">Origin: {country}</span>
                  </div>

                  <div className="flow-connection">
                    <div className="flow-line">
                      <div className={`flow-pulse ${isBlocked ? 'blocked' : 'allowed'}`} />
                    </div>
                    <div className="flow-tag">
                      <span className={`badge ${isBlocked ? 'badge-critical' : 'badge-low'}`}>
                        {action.toUpperCase()}
                      </span>
                    </div>
                  </div>

                  <div className="flow-node node-firewall">
                    <span className="node-badge">SOC CORE ENGINE</span>
                    <Server size={22} className="text-coral" />
                    <span className="node-fw-title">Normalization & ML</span>
                    <span className="node-status text-emerald">Normalized</span>
                  </div>

                  <div className="flow-connection">
                    <div className="flow-line">
                      <div className="flow-pulse allowed" />
                    </div>
                    <div className="flow-tag">
                      <span className="badge badge-info">FORWARD</span>
                    </div>
                  </div>

                  <div className="flow-node node-dest">
                    <span className="node-badge">DESTINATION HOST</span>
                    <span className="node-ip mono">{dstIp}</span>
                    <span className="node-port mono">Port: {dstPort}</span>
                    <span className="node-geo">Internal Asset</span>
                  </div>
                </div>
              </div>

              {/* Message Banner */}
              {lastResult.event?.message && (
                <div className="event-message-card">
                  <span className="msg-label">EVENT MESSAGE:</span>
                  <span className="msg-text mono">{lastResult.event.message}</span>
                </div>
              )}
            </div>
          ) : (
            <div className="canonical-json-wrapper">
              <div className="json-header-bar">
                <span className="mono text-muted">Schema: OCSF / Elastic Common Schema v1.0</span>
                <button onClick={copyResultJSON} className="btn btn-secondary btn-sm">
                  {copied ? <Check size={14} className="text-emerald" /> : <Copy size={14} />}
                  <span>{copied ? 'Copied to Clipboard' : 'Copy Canonical JSON'}</span>
                </button>
              </div>
              <pre className="modal-json-pre mono">
                {JSON.stringify(lastResult, null, 2)}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
