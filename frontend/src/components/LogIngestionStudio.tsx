import React, { useState, useRef } from 'react';
import {
  FileCode2,
  Sparkles,
  Send,
  Upload,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  Shield,
  Copy,
  Check,
  Activity,
  Globe2,
  Server,
  Zap,
  Network,
  Code2,
  FileSpreadsheet,
  Download,
  FileText,
  Trash2,
  Clipboard,
  Layers,
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
  const [activeMode, setActiveMode] = useState<'single' | 'batch' | 'file'>('single');
  const [batchText, setBatchText] = useState(
    'src=1.2.3.4 dst=10.5.2.4 action=deny country=CN msg="c2-beacon"\n' +
    'Aug 31 10:45:00 web-01 sshd[4192]: Failed password for root from 192.168.1.10 port 22\n' +
    'CEF:0|Palo Alto|PAN-OS|11.0|THREAT|C2|9|src=185.220.101.5 dst=10.0.0.1 action=deny\n' +
    '{"timestamp":"2026-08-31T11:00:00Z","src_ip":"10.0.0.8","action":"block","severity":"high"}'
  );
  const [resultTab, setResultTab] = useState<'visual' | 'json'>('visual');

  // File Upload State
  const [uploadedFile, setUploadedFile] = useState<{ name: string; size: number; lines: string[]; content: string } | null>(null);
  const [enrichmentProgress, setEnrichmentProgress] = useState<number>(0);
  const [enrichedBatchResults, setEnrichedBatchResults] = useState<NormalizedEvent[]>([]);
  const fileInputRef = useRef<HTMLInputElement>(null);

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
    setPipelineStep(1);
    const lines = batchText.split('\n').map((l) => l.trim()).filter(Boolean);
    try {
      await new Promise((r) => setTimeout(r, 150));
      setPipelineStep(2);
      await new Promise((r) => setTimeout(r, 150));
      setPipelineStep(3);

      const results = await onBatchIngest(lines);
      setPipelineStep(4);
      if (results.length > 0) {
        setLastResult(results[results.length - 1]);
        setEnrichedBatchResults(results);
      }
    } catch (err: unknown) {
      setErrorMessage(err instanceof Error ? err.message : 'Batch processing failed');
    } finally {
      setIsProcessing(false);
    }
  };

  const pasteFromClipboard = async (target: 'single' | 'batch') => {
    try {
      const text = await navigator.clipboard.readText();
      if (target === 'single') setLogText(text);
      else setBatchText(text);
    } catch {
      // ignore clipboard permission error
    }
  };

  const loadSampleBatch = () => {
    setBatchText(
      'src=1.2.3.4 dst=10.5.2.4 action=deny country=CN msg="c2-beacon"\n' +
      'Aug 31 10:45:00 web-01 sshd[4192]: Failed password for root from 192.168.1.10 port 22\n' +
      'CEF:0|Palo Alto|PAN-OS|11.0|THREAT|C2|9|src=185.220.101.5 dst=10.0.0.1 action=deny\n' +
      '{"timestamp":"2026-08-31T11:00:00Z","src_ip":"10.0.0.8","action":"block","severity":"high"}'
    );
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      if (content) {
        let lines: string[] = [];
        if (content.trim().startsWith('[') && content.trim().endsWith(']')) {
          try {
            const parsed = JSON.parse(content);
            if (Array.isArray(parsed)) {
              lines = parsed.map((item) => (typeof item === 'string' ? item : JSON.stringify(item)));
            }
          } catch {
            lines = content.split('\n').map((l) => l.trim()).filter(Boolean);
          }
        } else {
          lines = content.split('\n').map((l) => l.trim()).filter(Boolean);
        }

        setUploadedFile({
          name: file.name,
          size: file.size,
          lines,
          content,
        });
        setBatchText(content);
        setEnrichmentProgress(0);
        setEnrichedBatchResults([]);
      }
    };
    reader.readAsText(file);
  };

  const handleProcessAndEnrichFile = async () => {
    if (!uploadedFile || uploadedFile.lines.length === 0) return;
    setIsProcessing(true);
    setErrorMessage(null);
    setEnrichmentProgress(15);

    try {
      setEnrichmentProgress(35);
      await new Promise((r) => setTimeout(r, 200));
      setEnrichmentProgress(65);

      const results = await onBatchIngest(uploadedFile.lines);
      setEnrichmentProgress(100);
      setEnrichedBatchResults(results);
      if (results.length > 0) {
        setLastResult(results[results.length - 1]);
      }
    } catch (err: unknown) {
      setErrorMessage(err instanceof Error ? err.message : 'File processing & enrichment failed');
    } finally {
      setIsProcessing(false);
    }
  };

  const downloadEnrichedJSON = () => {
    if (enrichedBatchResults.length === 0) return;
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(enrichedBatchResults, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `enriched_${uploadedFile?.name || 'logs'}_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const downloadEnrichedCSV = () => {
    if (enrichedBatchResults.length === 0) return;
    const headers = ['Timestamp', 'Source', 'Action', 'Severity', 'Source IP', 'Destination IP', 'Country', 'Threat', 'Score'];
    const rows = enrichedBatchResults.map((e) => [
      e.timestamp || '',
      e.source || '',
      e.event?.action || '',
      e.event?.severity || e.severity || '',
      e.network?.source_ip || e.network?.src_ip || '',
      e.network?.destination_ip || e.network?.dst_ip || '',
      e.enrichment?.country || '',
      e.threat?.reputation || '',
      e.threat?.score || '',
    ]);

    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map((r) => r.map((c) => `"${c}"`).join(','))].join('\n');
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', encodeURI(csvContent));
    downloadAnchor.setAttribute('download', `enriched_${uploadedFile?.name || 'logs'}_${Date.now()}.csv`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
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

  const batchLineCount = batchText.split('\n').filter((l) => l.trim()).length;

  return (
    <div className="ingestion-studio-container">
      {/* Studio Header & Mode Tabs */}
      <div className="studio-top glass-panel">
        <div className="card-header-flex">
          <div>
            <div className="badge-row" style={{ display: 'flex', gap: '8px', marginBottom: '6px' }}>
              <span className="badge badge-purple">Multi-Format Pipeline</span>
              <span className="badge badge-cyan">Zero-Loss Normalization</span>
            </div>
            <h2 className="card-title">Live Log Ingestion &amp; Pipeline Studio</h2>
            <p className="card-subtitle">
              Feed raw multi-vendor security telemetry directly or upload files for automated canonical normalization and threat enrichment
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
              Batch Multi-Line
            </button>
            <button
              className={`mode-tab-btn ${activeMode === 'file' ? 'active' : ''}`}
              onClick={() => setActiveMode('file')}
            >
              📁 Upload &amp; Enrich File
            </button>
          </div>
        </div>

        {/* Quick Presets Bar */}
        {activeMode !== 'file' && (
          <div className="preset-bar">
            <span className="preset-label">
              <Sparkles size={14} className="text-coral" />
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
                  <span className="preset-chip-name">{p.name}</span>
                  <span className="preset-format-tag">{p.format}</span>
                </button>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* FILE UPLOAD & ENRICH VIEW */}
      {activeMode === 'file' && (
        <div className="file-upload-workspace glass-panel">
          <div className="file-upload-dropzone" onClick={() => fileInputRef.current?.click()}>
            <input
              type="file"
              ref={fileInputRef}
              onChange={handleFileUpload}
              accept=".log,.txt,.json,.csv,.syslog,.cef,.leef"
              style={{ display: 'none' }}
            />
            <div className="dropzone-content">
              <div className="dropzone-icon-box">
                <Upload size={32} className="text-coral" />
              </div>
              <h3 className="dropzone-title">
                {uploadedFile ? `Loaded: ${uploadedFile.name}` : 'Click to Browse or Drag & Drop Log File'}
              </h3>
              <p className="dropzone-subtitle">
                Supported formats: <strong>.log, .txt, .json, .csv, .syslog, .cef, .leef</strong>
              </p>
              {uploadedFile && (
                <div className="file-meta-tags">
                  <span className="badge badge-cyan mono">{(uploadedFile.size / 1024).toFixed(1)} KB</span>
                  <span className="badge badge-purple mono">{uploadedFile.lines.length} Events Detected</span>
                  <span className="badge badge-low">Ready for Normalization &amp; Enrichment</span>
                </div>
              )}
            </div>
          </div>

          {/* File Preview & Actions */}
          {uploadedFile && (
            <div className="file-preview-section">
              <div className="file-preview-header">
                <div className="preview-title-wrap">
                  <FileText size={16} className="text-muted" />
                  <span className="preview-title">File Preview (First 5 lines):</span>
                </div>
                <button
                  onClick={handleProcessAndEnrichFile}
                  disabled={isProcessing}
                  className="btn btn-primary btn-enrich-all"
                >
                  {isProcessing ? <Zap size={16} className="animate-spin" /> : <Sparkles size={16} />}
                  <span>{isProcessing ? 'Normalizing & Enriching File...' : '⚡ Process & Enrich File (Normalize + GeoIP + ML)'}</span>
                </button>
              </div>

              <pre className="file-preview-box mono">
                {uploadedFile.lines.slice(0, 5).join('\n')}
                {uploadedFile.lines.length > 5 ? `\n... and ${uploadedFile.lines.length - 5} more lines` : ''}
              </pre>

              {/* Real-time Progress Bar */}
              {isProcessing && (
                <div className="enrichment-progress-bar-wrap">
                  <div className="progress-info-row">
                    <span>Batch Normalization &amp; Enrichment in progress...</span>
                    <span className="mono">{enrichmentProgress}%</span>
                  </div>
                  <div className="progress-track">
                    <div className="progress-fill" style={{ width: `${enrichmentProgress}%` }} />
                  </div>
                </div>
              )}

              {/* Enriched Summary & Download Buttons */}
              {enrichedBatchResults.length > 0 && (
                <div className="enriched-file-results-card">
                  <div className="results-header-flex">
                    <div className="results-badge-group">
                      <CheckCircle2 size={20} className="text-emerald" />
                      <div>
                        <h4 className="results-title">Successfully Processed &amp; Enriched {enrichedBatchResults.length} Events</h4>
                        <p className="results-subtitle">Canonical schema mapped, GeoIP resolved, and ML anomaly scored</p>
                      </div>
                    </div>

                    <div className="download-btn-group">
                      <button onClick={downloadEnrichedJSON} className="btn btn-secondary btn-sm">
                        <Download size={14} className="text-cyan" />
                        <span>Download Enriched JSON</span>
                      </button>
                      <button onClick={downloadEnrichedCSV} className="btn btn-secondary btn-sm">
                        <FileSpreadsheet size={14} className="text-emerald" />
                        <span>Download Enriched CSV</span>
                      </button>
                    </div>
                  </div>

                  <div className="enriched-kpi-grid">
                    <div className="enriched-kpi-box">
                      <span className="kpi-lbl">Total Records</span>
                      <span className="kpi-val mono">{enrichedBatchResults.length}</span>
                    </div>
                    <div className="enriched-kpi-box">
                      <span className="kpi-lbl">Threats Flagged</span>
                      <span className="kpi-val mono text-coral">
                        {enrichedBatchResults.filter((e) => e.threat?.reputation === 'suspicious' || e.threat?.reputation === 'malicious').length}
                      </span>
                    </div>
                    <div className="enriched-kpi-box">
                      <span className="kpi-lbl">Blocked / Denied</span>
                      <span className="kpi-val mono text-amber">
                        {enrichedBatchResults.filter((e) => (e.event?.action || '').toLowerCase().includes('deny') || (e.event?.action || '').toLowerCase().includes('block')).length}
                      </span>
                    </div>
                    <div className="enriched-kpi-box">
                      <span className="kpi-lbl">Foreign GeoIPs</span>
                      <span className="kpi-val mono text-cyan">
                        {enrichedBatchResults.filter((e) => e.enrichment?.country && e.enrichment.country !== 'US' && e.enrichment.country !== 'IN').length}
                      </span>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* SINGLE & BATCH INGESTION MODES */}
      {activeMode !== 'file' && (
        <div className="studio-grid">
          {/* Ingestion Editor Box */}
          <div className="glass-panel editor-panel">
            {/* Editor Action Header */}
            <div className="editor-top-bar">
              <div className="editor-indicator">
                <FileCode2 size={18} className="text-coral" />
                <span className="editor-label">
                  {activeMode === 'single' ? 'Single Telemetry Payload' : 'Batch Multi-Line Stream'}
                </span>
              </div>

              <div className="editor-top-controls">
                <span className="format-detect-badge">
                  <span className="pulse-dot online" style={{ width: '6px', height: '6px' }} />
                  <span>{detectFormatPreview(activeMode === 'single' ? logText : batchText)}</span>
                </span>

                {/* Quick Editor Actions */}
                <div className="editor-micro-actions">
                  <button
                    onClick={() => pasteFromClipboard(activeMode)}
                    className="micro-btn"
                    title="Paste from clipboard"
                  >
                    <Clipboard size={13} />
                    <span>Paste</span>
                  </button>
                  <button
                    onClick={() => (activeMode === 'single' ? setLogText('') : setBatchText(''))}
                    className="micro-btn"
                    title="Clear editor"
                  >
                    <Trash2 size={13} />
                    <span>Clear</span>
                  </button>
                </div>
              </div>
            </div>

            {/* Editor Textarea */}
            {activeMode === 'single' ? (
              <div className="modern-editor-wrapper">
                <textarea
                  className="log-textarea mono"
                  value={logText}
                  onChange={(e) => setLogText(e.target.value)}
                  placeholder="Paste raw Syslog, CEF, LEEF, JSON, or Key-Value security log here..."
                  rows={6}
                />
                <div className="editor-footer-info">
                  <span className="editor-stat-chip">
                    1 Event • {logText.length} Characters
                  </span>
                  <span className="editor-hint-chip">
                    Tip: Press Process Event to trigger canonical pipeline
                  </span>
                </div>
              </div>
            ) : (
              <div className="modern-editor-wrapper">
                <textarea
                  className="log-textarea mono"
                  value={batchText}
                  onChange={(e) => setBatchText(e.target.value)}
                  placeholder="Paste multiple log lines (one event per line)..."
                  rows={8}
                />
                <div className="editor-footer-info">
                  <span className="editor-stat-chip">
                    <Layers size={13} />
                    <span>{batchLineCount} Events in Stream</span>
                  </span>
                  <button onClick={loadSampleBatch} className="load-sample-link">
                    + Load Multi-Vendor Sample
                  </button>
                </div>
              </div>
            )}

            {/* Run Button Action */}
            <div className="editor-actions">
              <button
                className="btn btn-primary btn-run-large"
                onClick={activeMode === 'single' ? handleProcess : handleBatchProcess}
                disabled={isProcessing || (activeMode === 'single' ? !logText.trim() : !batchText.trim())}
              >
                {isProcessing ? (
                  <>
                    <Activity size={18} className="animate-spin" />
                    <span>Normalizing &amp; Scoring Stream...</span>
                  </>
                ) : (
                  <>
                    <Send size={18} />
                    <span>
                      {activeMode === 'single' ? '⚡ Process & Normalize Event' : `🚀 Normalize ${batchLineCount} Batch Events`}
                    </span>
                  </>
                )}
              </button>
            </div>

            {errorMessage && (
              <div className="pipeline-error-box">
                <AlertTriangle size={18} />
                <span>{errorMessage}</span>
              </div>
            )}

            {/* Ingestion Pipeline Execution Progress Steps */}
            <div className="pipeline-tracker">
              <span className="tracker-title">Pipeline Execution Telemetry</span>
              <div className="pipeline-steps-row">
                {pipelineStages.map((stg, idx) => {
                  const stepNum = idx + 1;
                  const isDone = pipelineStep > stepNum || (pipelineStep === 4 && stepNum === 4);
                  const isActive = pipelineStep === stepNum && isProcessing;

                  return (
                    <div
                      key={stg.label}
                      className={`pipeline-step-item ${isDone ? 'done' : ''} ${isActive ? 'active' : ''}`}
                    >
                      <div className="step-num-circle">
                        {isDone ? <Check size={13} /> : stepNum}
                      </div>
                      <div className="step-texts">
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

          {/* Canonical Output & Interactive Visualizations */}
          <div className="glass-panel output-panel">
            <div className="output-top-bar">
              <div className="output-title-group">
                <Shield size={20} className="text-coral" />
                <div>
                  <h3 className="output-heading">Post-Normalization Intelligence</h3>
                  <span className="output-sub">Standardized canonical entity structure</span>
                </div>
              </div>

              <div className="output-view-toggle">
                <button
                  className={`toggle-tab-btn ${resultTab === 'visual' ? 'active' : ''}`}
                  onClick={() => setResultTab('visual')}
                >
                  <Network size={14} />
                  <span>Visual Flow Matrix</span>
                </button>
                <button
                  className={`toggle-tab-btn ${resultTab === 'json' ? 'active' : ''}`}
                  onClick={() => setResultTab('json')}
                >
                  <Code2 size={14} />
                  <span>Canonical JSON</span>
                </button>
              </div>
            </div>

            {/* TAB 1: VISUAL FLOW MATRIX */}
            {resultTab === 'visual' && (
              <div className="visual-matrix-wrap">
                {/* 4 Telemetry Metric Chips */}
                <div className="post-kpi-row">
                  <div className="post-kpi-card">
                    <span className="kpi-label">Security Action</span>
                    <div className="kpi-value-wrap">
                      <span className={`badge ${isBlocked ? 'badge-critical' : 'badge-low'}`}>
                        {action.toUpperCase()}
                      </span>
                    </div>
                  </div>

                  <div className="post-kpi-card">
                    <span className="kpi-label">Geo Origin</span>
                    <div className="kpi-value-wrap">
                      <Globe2 size={15} className="text-cyan" />
                      <span className="mono kpi-val-text">{country}</span>
                    </div>
                  </div>

                  <div className="post-kpi-card">
                    <span className="kpi-label">Threat Intel</span>
                    <div className="kpi-value-wrap">
                      <span className={`badge ${reputation === 'suspicious' || reputation === 'malicious' ? 'badge-critical' : 'badge-low'}`}>
                        {reputation.toUpperCase()}
                      </span>
                    </div>
                  </div>

                  <div className="post-kpi-card">
                    <span className="kpi-label">Engine Latency</span>
                    <div className="kpi-value-wrap">
                      <Zap size={15} className="text-amber" />
                      <span className="mono kpi-val-text">&lt; 1.8ms</span>
                    </div>
                  </div>
                </div>

                {/* Animated Network Flow Diagram */}
                <div className="network-flow-card">
                  <div className="flow-node source-node">
                    <div className="node-icon-box">
                      <Server size={20} />
                    </div>
                    <span className="node-title">Source Host</span>
                    <span className="node-ip mono">{srcIp}</span>
                    <span className="node-port mono">Port: {srcPort}</span>
                  </div>

                  <div className="flow-connector">
                    <div className="connector-line">
                      <div className="pulse-flow-dot" />
                    </div>
                    <span className="flow-action-badge">{action.toUpperCase()}</span>
                  </div>

                  <div className="flow-node core-node">
                    <div className="node-icon-box core-icon">
                      <Shield size={22} />
                    </div>
                    <span className="node-title">SOC Core Engine</span>
                    <span className={`badge badge-${sev === 'critical' ? 'critical' : sev === 'high' ? 'high' : 'low'}`}>
                      {sev.toUpperCase()} SEVERITY
                    </span>
                    <span className="node-sub mono">Enriched &amp; Scored</span>
                  </div>

                  <div className="flow-connector">
                    <div className="connector-line">
                      <div className="pulse-flow-dot delay" />
                    </div>
                    <span className="flow-dest-badge">CANONICAL</span>
                  </div>

                  <div className="flow-node dest-node">
                    <div className="node-icon-box">
                      <Server size={20} />
                    </div>
                    <span className="node-title">Destination Host</span>
                    <span className="node-ip mono">{dstIp}</span>
                    <span className="node-port mono">Port: {dstPort}</span>
                  </div>
                </div>
              </div>
            )}

            {/* TAB 2: CANONICAL JSON VIEWER */}
            {resultTab === 'json' && (
              <div className="json-result-wrap">
                <div className="json-header-actions">
                  <span className="json-title mono">Canonical Standard Schema</span>
                  {lastResult && (
                    <button onClick={copyResultJSON} className="btn-copy-json">
                      {copied ? <Check size={14} className="text-emerald" /> : <Copy size={14} />}
                      <span>{copied ? 'Copied' : 'Copy JSON'}</span>
                    </button>
                  )}
                </div>
                <pre className="output-json-pre mono">
                  {lastResult
                    ? JSON.stringify(lastResult, null, 2)
                    : '// Normalized canonical JSON output will appear here after ingestion'}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
