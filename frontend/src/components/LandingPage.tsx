import React, { useState } from 'react';
import {
  ShieldCheck,
  Zap,
  Layers,
  Globe2,
  Cpu,
  ArrowRight,
  Sparkles,
  CheckCircle2,
  Play,
  Terminal,
  Activity,
  Database,
} from 'lucide-react';
import type { NormalizedEvent } from '../types';

interface LandingPageProps {
  setCurrentView: (view: string) => void;
  onIngest: (rawLog: string) => Promise<NormalizedEvent>;
  eventCount: number;
}

export const LandingPage: React.FC<LandingPageProps> = ({
  setCurrentView,
  onIngest,
  eventCount,
}) => {
  const [demoInput, setDemoInput] = useState(
    'CEF:0|Palo Alto Networks|PAN-OS|11.0|THREAT|C2-Beacon|9|src=1.2.3.4 dst=10.5.2.4 msg=malware-beacon-c2 action=deny'
  );
  const [demoResult, setDemoResult] = useState<NormalizedEvent | null>(null);
  const [isNormalizing, setIsNormalizing] = useState(false);

  const DEMO_PRESETS = [
    {
      label: 'Palo Alto CEF',
      val: 'CEF:0|Palo Alto Networks|PAN-OS|11.0|THREAT|C2-Beacon|9|src=1.2.3.4 dst=10.5.2.4 msg=malware-beacon-c2 action=deny',
    },
    {
      label: 'Firewall Key-Value',
      val: 'src=10.0.0.5 dst=8.8.8.8 action=deny port=443 protocol=TCP bytes=1420',
    },
    {
      label: 'Linux SSH Syslog',
      val: 'Aug 30 10:45:00 web-01 sshd[4192]: Failed password for invalid user admin from 192.168.1.10 port 22 ssh2',
    },
    {
      label: 'Cloud JSON API',
      val: '{"timestamp":"2026-08-30T10:42:00Z","host":"api-gateway","source":"api","event_type":"authentication","severity":"WARN","message":"token expired","src_ip":"10.0.0.8"}',
    },
  ];

  const handleTestNormalize = async () => {
    if (!demoInput.trim()) return;
    setIsNormalizing(true);
    try {
      const res = await onIngest(demoInput.trim());
      setDemoResult(res);
    } catch (e) {
      console.error('Demo normalization failed:', e);
    } finally {
      setIsNormalizing(false);
    }
  };

  const pillars = [
    {
      icon: Layers,
      color: '#56B4FF',
      title: 'Heterogeneous Ingestion',
      desc: 'Ingests RFC3164 Syslog, CEF, LEEF, JSON, and Key-Value log streams with zero vendor lock-in.',
    },
    {
      icon: ShieldCheck,
      color: '#34B1AA',
      title: 'Canonical Normalization',
      desc: 'Transforms fragmented vendor formats into a standardized, validated schema with unified field mappings.',
    },
    {
      icon: Globe2,
      color: '#F29F67',
      title: 'GeoIP & CTI Enrichment',
      desc: 'Automatically tags autonomous system numbers, country coordinates, and IP reputation intelligence.',
    },
    {
      icon: Cpu,
      color: '#E0B50F',
      title: 'Random Forest ML Engine',
      desc: 'Lightweight scikit-learn model calculates real-time probabilistic anomaly scores and threat postures.',
    },
    {
      icon: Activity,
      color: '#34B1AA',
      title: 'Real-Time Telemetry',
      desc: 'Visual velocity timeline, threat gauges, severity distributions, and source telemetry charts.',
    },
    {
      icon: Database,
      color: '#ef4444',
      title: 'SIEM & SOC Ready',
      desc: 'Search, filter, inspect canonical JSON payloads, and export datasets via high-throughput REST APIs.',
    },
  ];

  const pipelineStages = [
    { step: '01', name: 'Collector', desc: 'Accept raw logs via REST API or file stream' },
    { step: '02', name: 'Detector', desc: 'Auto-identify Syslog, CEF, LEEF, JSON, or KV format' },
    { step: '03', name: 'Parser', desc: 'Extract vendor-specific key pairs & metadata' },
    { step: '04', name: 'Normalizer', desc: 'Map into unified canonical SIEM schema' },
    { step: '05', name: 'Enrichment', desc: 'Add GeoIP location & Threat Intel reputation' },
    { step: '06', name: 'ML Classifier', desc: 'Random Forest scores multi-factor anomaly risk' },
    { step: '07', name: 'Delivery', desc: 'Push to SOC Dashboard, Event Store & SIEM' },
  ];

  return (
    <div className="landing-container fade-in">
      {/* Hero Section */}
      <section className="landing-hero">
        <div className="hero-badge-pill">
          <Sparkles size={14} className="text-cyan" />
          <span>Vendor-Agnostic Cybersecurity Platform</span>
          <span className="pill-dot" />
          <span className="text-muted">SIH 2026 Innovation</span>
        </div>

        <h1 className="hero-title">
          Universal Log Framework
        </h1>
        <p className="hero-subtitle">
          Transform fragmented, multi-vendor security telemetry into canonical schemas, enriched with real-time GeoIP, threat intelligence, and machine learning anomaly detection.
        </p>

        <div className="hero-cta-group">
          <button
            onClick={() => setCurrentView('analytics')}
            className="btn btn-primary btn-lg"
          >
            <Play size={18} />
            <span>Launch SOC Dashboard</span>
            <ArrowRight size={16} />
          </button>

          <button
            onClick={() => setCurrentView('ingest')}
            className="btn btn-secondary btn-lg"
          >
            <Zap size={18} className="text-accent" />
            <span>Open Ingestion Studio</span>
          </button>

          <button
            onClick={() => setCurrentView('api-docs')}
            className="btn btn-secondary btn-lg"
          >
            <Terminal size={18} />
            <span>REST API Specs</span>
          </button>
        </div>

        {/* Hero Benchmark Metric Cards */}
        <div className="hero-stats-row">
          <div className="hero-stat-card glass-panel">
            <span className="hero-stat-val text-cyan">99.9%</span>
            <span className="hero-stat-lbl">Parser Accuracy</span>
          </div>
          <div className="hero-stat-card glass-panel">
            <span className="hero-stat-val text-emerald">&lt;2ms</span>
            <span className="hero-stat-lbl">Inference Latency</span>
          </div>
          <div className="hero-stat-card glass-panel">
            <span className="hero-stat-val text-purple">5+ Formats</span>
            <span className="hero-stat-lbl">Syslog, CEF, LEEF, JSON, KV</span>
          </div>
          <div className="hero-stat-card glass-panel">
            <span className="hero-stat-val text-accent">{eventCount} Events</span>
            <span className="hero-stat-lbl">Currently in Store</span>
          </div>
        </div>
      </section>

      {/* Live Normalization Playground Widget */}
      <section className="landing-playground-section">
        <div className="glass-panel playground-card">
          <div className="card-header-flex">
            <div>
              <div className="badge badge-cyan mb-8">
                <Terminal size={12} /> Interactive Playground
              </div>
              <h2 className="section-title">Test Live Log Normalization</h2>
              <p className="card-subtitle">
                Select a preset or paste any raw security log to witness real-time format detection & schema enrichment.
              </p>
            </div>
            <button
              onClick={() => setCurrentView('ingest')}
              className="btn btn-secondary btn-sm"
            >
              Full Ingestion Studio <ArrowRight size={14} />
            </button>
          </div>

          {/* Preset Buttons */}
          <div className="playground-presets">
            <span className="preset-title">Presets:</span>
            {DEMO_PRESETS.map((p, idx) => (
              <button
                key={idx}
                onClick={() => setDemoInput(p.val)}
                className="preset-btn-chip"
              >
                {p.label}
              </button>
            ))}
          </div>

          <div className="playground-editor-grid">
            <div className="playground-input-col">
              <span className="col-label">Raw Telemetry Input:</span>
              <textarea
                value={demoInput}
                onChange={(e) => setDemoInput(e.target.value)}
                className="playground-textarea mono"
                rows={4}
                placeholder="Paste log..."
              />
              <button
                onClick={handleTestNormalize}
                disabled={isNormalizing}
                className="btn btn-primary btn-sm mt-8"
              >
                <Zap size={14} />
                <span>{isNormalizing ? 'Processing...' : 'Normalize & Score Log'}</span>
              </button>
            </div>

            <div className="playground-output-col">
              <span className="col-label">Canonical Normalized Output:</span>
              <div className="playground-json-box mono">
                {demoResult ? (
                  <pre className="json-pre-text">
                    {JSON.stringify(demoResult, null, 2)}
                  </pre>
                ) : (
                  <div className="playground-placeholder">
                    <CheckCircle2 size={24} className="text-muted" />
                    <span>Click 'Normalize & Score Log' above to see the canonical schema response</span>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Six Feature Pillars Grid */}
      <section className="landing-pillars-section">
        <div className="section-header-center">
          <span className="badge badge-purple mb-8">Architectural Capabilities</span>
          <h2 className="section-title">Engineered for Enterprise SOC Operations</h2>
          <p className="section-subtitle">
            Built to solve the pain of heterogeneous log silos across modern multi-cloud and on-premise infrastructure.
          </p>
        </div>

        <div className="pillars-grid">
          {pillars.map((pil, idx) => {
            const Icon = pil.icon;
            return (
              <div key={idx} className="pillar-card glass-panel">
                <div className="pillar-icon-box" style={{ backgroundColor: `${pil.color}15`, color: pil.color, borderColor: `${pil.color}35` }}>
                  <Icon size={22} />
                </div>
                <h3 className="pillar-title">{pil.title}</h3>
                <p className="pillar-desc">{pil.desc}</p>
              </div>
            );
          })}
        </div>
      </section>

      {/* Pipeline Flow Architecture */}
      <section className="landing-pipeline-flow-section">
        <div className="glass-panel pipeline-flow-card">
          <div className="section-header-center">
            <span className="badge badge-cyan mb-8">Zero-Loss Data Flow</span>
            <h2 className="section-title">End-to-End Processing Architecture</h2>
            <p className="section-subtitle">
              Every incoming log progresses through a structured 7-stage processing lifecycle before visualization.
            </p>
          </div>

          <div className="pipeline-flow-timeline">
            {pipelineStages.map((stg, idx) => (
              <div key={idx} className="flow-timeline-step">
                <div className="flow-step-circle mono">{stg.step}</div>
                <h4 className="flow-step-name">{stg.name}</h4>
                <p className="flow-step-desc">{stg.desc}</p>
                {idx < pipelineStages.length - 1 && (
                  <div className="flow-step-connector" />
                )}
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Comparison: Why Normalization Matters */}
      <section className="landing-comparison-section">
        <div className="section-header-center">
          <span className="badge badge-amber mb-8">The Normalization Advantage</span>
          <h2 className="section-title">Before vs After Canonical Standard</h2>
        </div>

        <div className="comparison-grid">
          <div className="glass-panel comparison-card border-red">
            <div className="comparison-header">
              <div className="comparison-badge red">BEFORE</div>
              <h3 className="comparison-title">Fragmented Vendor Logs</h3>
            </div>
            <ul className="comparison-list">
              <li>❌ Inconsistent field keys (<code>src</code> vs <code>source_ip</code> vs <code>saddr</code> vs <code>clientIP</code>)</li>
              <li>❌ Threat intelligence missing from raw logs</li>
              <li>❌ Analysts must handcraft parser regexes per device</li>
              <li>❌ Difficult cross-device correlation during incidents</li>
              <li>❌ High computational overhead in downstream SIEMs</li>
            </ul>
          </div>

          <div className="glass-panel comparison-card border-green">
            <div className="comparison-header">
              <div className="comparison-badge green">AFTER (UNIVERSAL LOG FRAMEWORK)</div>
              <h3 className="comparison-title">Unified Canonical Schema</h3>
            </div>
            <ul className="comparison-list">
              <li>✅ Standardized schema structure (<code>network</code>, <code>event</code>, <code>threat</code>, <code>enrichment</code>)</li>
              <li>✅ Enriched GeoIP location, ASN, and reputation flags</li>
              <li>✅ Instant machine learning anomaly scoring per event</li>
              <li>✅ Single query format across all security telemetry</li>
              <li>✅ Zero-loss raw message retention for forensics</li>
            </ul>
          </div>
        </div>
      </section>

      {/* Bottom CTA Banner */}
      <section className="landing-cta-banner glass-panel">
        <div className="cta-banner-content">
          <div className="cta-icon-wrapper">
            <ShieldCheck size={36} className="text-cyan" />
          </div>
          <div>
            <h2 className="cta-title">Ready to Explore the Live SOC Dashboard?</h2>
            <p className="cta-desc">
              Monitor real-time security events, inspect ML risk postures, and test heterogeneous log normalization in action.
            </p>
          </div>
        </div>
        <div className="cta-btn-wrap">
          <button
            onClick={() => setCurrentView('analytics')}
            className="btn btn-primary btn-lg"
          >
            <span>Launch SOC Dashboard</span>
            <ArrowRight size={16} />
          </button>
        </div>
      </section>
    </div>
  );
};
