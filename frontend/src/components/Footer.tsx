import React from 'react';
import { ShieldCheck, Cpu, Terminal, ExternalLink, Activity } from 'lucide-react';
import type { HealthStatus } from '../types';

interface FooterProps {
  setCurrentView: (view: string) => void;
  health: HealthStatus | null;
  eventCount: number;
}

export const Footer: React.FC<FooterProps> = ({
  setCurrentView,
  health,
  eventCount,
}) => {
  const isOnline = !!health;

  return (
    <footer className="footer-container">
      <div className="container footer-content-grid">
        {/* Col 1: Brand & Overview */}
        <div className="footer-brand-col">
          <div className="footer-brand-header">
            <div className="footer-logo-box">
              <ShieldCheck size={20} className="text-cyan" />
            </div>
            <span className="footer-brand-title">UNIVERSAL LOG FRAMEWORK</span>
          </div>
          <p className="footer-desc">
            A vendor-neutral cybersecurity log processing and intelligence framework. Ingests heterogeneous security telemetry, automatically detects formats, standardizes canonical schemas, enriches threat intelligence, and scores anomaly risk.
          </p>
          <div className="footer-badges-row">
            <span className="badge badge-cyan">FastAPI Backend</span>
            <span className="badge badge-purple">Random Forest ML</span>
            <span className="badge badge-info">React 18 SPA</span>
          </div>
        </div>

        {/* Col 2: Platform Navigation */}
        <div className="footer-links-col">
          <h4 className="footer-col-title">Platform Views</h4>
          <ul className="footer-links-list">
            <li>
              <button onClick={() => setCurrentView('landing')} className="footer-link-btn">
                Home / Overview
              </button>
            </li>
            <li>
              <button onClick={() => setCurrentView('analytics')} className="footer-link-btn">
                SOC Analytics Dashboard
              </button>
            </li>
            <li>
              <button onClick={() => setCurrentView('ingest')} className="footer-link-btn">
                Log Ingestion Studio
              </button>
            </li>
            <li>
              <button onClick={() => setCurrentView('events')} className="footer-link-btn">
                SIEM Event Explorer
              </button>
            </li>
            <li>
              <button onClick={() => setCurrentView('pulse')} className="footer-link-btn">
                Security Pulse & Alerts
              </button>
            </li>
            <li>
              <button onClick={() => setCurrentView('ml')} className="footer-link-btn">
                ML Anomaly Engine
              </button>
            </li>
          </ul>
        </div>

        {/* Col 3: Supported Formats & Standards */}
        <div className="footer-links-col">
          <h4 className="footer-col-title">Supported Formats</h4>
          <ul className="footer-tags-list">
            <li className="format-tag-item">
              <Terminal size={12} />
              <span>RFC3164 / RFC5424 Syslog</span>
            </li>
            <li className="format-tag-item">
              <Terminal size={12} />
              <span>Common Event Format (CEF)</span>
            </li>
            <li className="format-tag-item">
              <Terminal size={12} />
              <span>Log Event Extended Format (LEEF)</span>
            </li>
            <li className="format-tag-item">
              <Terminal size={12} />
              <span>Structured JSON Security Logs</span>
            </li>
            <li className="format-tag-item">
              <Terminal size={12} />
              <span>Key-Value Firewall Telemetry</span>
            </li>
          </ul>
        </div>

        {/* Col 4: Engine Status & Telemetry */}
        <div className="footer-status-col">
          <h4 className="footer-col-title">Engine Telemetry</h4>
          <div className="footer-telemetry-card glass-panel">
            <div className="telemetry-status-row">
              <div className="telemetry-node">
                <span className={`pulse-dot ${isOnline ? 'online' : 'critical'}`} />
                <span>Backend Core: <strong>{isOnline ? 'Online' : 'Disconnected'}</strong></span>
              </div>
              <span className="uptime-pill mono">
                {health ? `${health.uptime_seconds}s up` : 'Offline'}
              </span>
            </div>

            <div className="telemetry-detail-row">
              <span>Event Store Buffer:</span>
              <strong className="mono">{eventCount} events</strong>
            </div>

            <div className="telemetry-detail-row">
              <span>ML Classifier:</span>
              <strong className="mono">RandomForest (100 est)</strong>
            </div>

            <div className="telemetry-footer-btn-row">
              <button onClick={() => setCurrentView('api-docs')} className="btn btn-secondary btn-sm full-width">
                <Cpu size={14} />
                <span>View API Docs</span>
                <ExternalLink size={12} />
              </button>
            </div>
          </div>
        </div>
      </div>

      <div className="footer-bottom-bar">
        <div className="container footer-bottom-flex">
          <span className="copyright-text">
            © 2026 Universal Log Framework • Built for SIH Cybersecurity Innovation
          </span>
          <div className="footer-meta-tags">
            <span className="meta-tag"><Activity size={12} /> Canonical v1.2</span>
            <span className="meta-tag">FastAPI REST & WebSocket Ready</span>
          </div>
        </div>
      </div>
    </footer>
  );
};
