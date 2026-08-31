import React, { useState } from 'react';
import {
  AlertOctagon,
  Flame,
  Server,
  Clock,
  ShieldAlert,
  Lock,
  Ban,
  FileCheck,
  Zap,
  CheckCircle2,
  Timer,
} from 'lucide-react';
import type { AlertItem, IncidentItem, AssetItem } from '../types';

interface SecurityPulseProps {
  alerts: AlertItem[];
  incidents: IncidentItem[];
  assets: AssetItem[];
}

export const SecurityPulse: React.FC<SecurityPulseProps> = ({
  alerts,
  incidents,
  assets,
}) => {
  const [activePlaybookAction, setActivePlaybookAction] = useState<string | null>(null);

  const executePlaybook = (actionName: string) => {
    setActivePlaybookAction(actionName);
    setTimeout(() => {
      setActivePlaybookAction(null);
    }, 2500);
  };

  return (
    <div className="security-pulse-container">
      {/* Top Banner: Incident SLAs & Automated Playbooks */}
      <div className="glass-panel pulse-banner">
        <div className="pulse-banner-info">
          <div className="badge-row" style={{ display: 'flex', gap: '8px', marginBottom: '6px' }}>
            <span className="badge badge-critical">Live Incident Operations</span>
            <span className="badge badge-low">Automated Response Ready</span>
          </div>
          <h2 className="card-title" style={{ fontSize: '1.3rem' }}>Security Operations Center (SOC) Queue</h2>
          <p className="card-subtitle" style={{ fontSize: '0.86rem' }}>
            Real-time correlation, multi-vector anomaly escalation, and instant automated response playbooks
          </p>
        </div>

        <div className="pulse-sla-metrics">
          <div className="sla-metric-card">
            <div className="sla-top">
              <span className="sla-label">MTTD (Mean Time to Detect)</span>
              <Timer size={14} className="text-cyan" />
            </div>
            <span className="sla-val mono">&lt; 1.4 sec</span>
            <span className="sla-sub">Real-time event pipeline</span>
          </div>

          <div className="sla-metric-card">
            <div className="sla-top">
              <span className="sla-label">Critical Incident SLA</span>
              <Zap size={14} className="text-coral" />
            </div>
            <span className="sla-val mono">15 min target</span>
            <span className="sla-sub text-emerald">100% compliant</span>
          </div>
        </div>
      </div>

      {/* Automated Response Playbooks Bar */}
      <div className="glass-panel playbook-bar">
        <div className="playbook-header">
          <ShieldAlert size={18} className="text-coral" />
          <span className="playbook-title">Automated Incident Response Playbooks</span>
        </div>

        <div className="playbook-actions-grid">
          <button
            onClick={() => executePlaybook('block_ip')}
            className={`playbook-btn ${activePlaybookAction === 'block_ip' ? 'executed' : ''}`}
          >
            {activePlaybookAction === 'block_ip' ? <CheckCircle2 size={16} className="text-emerald" /> : <Ban size={16} className="text-coral" />}
            <div className="playbook-btn-text">
              <span className="playbook-btn-name">Block Malicious IP</span>
              <span className="playbook-btn-sub">Push rule to perimeter firewall</span>
            </div>
          </button>

          <button
            onClick={() => executePlaybook('isolate_host')}
            className={`playbook-btn ${activePlaybookAction === 'isolate_host' ? 'executed' : ''}`}
          >
            {activePlaybookAction === 'isolate_host' ? <CheckCircle2 size={16} className="text-emerald" /> : <Lock size={16} className="text-amber" />}
            <div className="playbook-btn-text">
              <span className="playbook-btn-name">Isolate Target Node</span>
              <span className="playbook-btn-sub">Quarantine host VLAN traffic</span>
            </div>
          </button>

          <button
            onClick={() => executePlaybook('revoke_token')}
            className={`playbook-btn ${activePlaybookAction === 'revoke_token' ? 'executed' : ''}`}
          >
            {activePlaybookAction === 'revoke_token' ? <CheckCircle2 size={16} className="text-emerald" /> : <Zap size={16} className="text-cyan" />}
            <div className="playbook-btn-text">
              <span className="playbook-btn-name">Revoke Active Tokens</span>
              <span className="playbook-btn-sub">Invalidate sessions across API gateway</span>
            </div>
          </button>

          <button
            onClick={() => executePlaybook('generate_report')}
            className={`playbook-btn ${activePlaybookAction === 'generate_report' ? 'executed' : ''}`}
          >
            {activePlaybookAction === 'generate_report' ? <CheckCircle2 size={16} className="text-emerald" /> : <FileCheck size={16} className="text-blue" />}
            <div className="playbook-btn-text">
              <span className="playbook-btn-name">Export Incident PDF</span>
              <span className="playbook-btn-sub">Compliance-ready audit log</span>
            </div>
          </button>
        </div>
      </div>

      {/* Three Columns Grid */}
      <div className="pulse-grid">
        {/* Column 1: Live Alert Stream */}
        <div className="glass-panel pulse-column">
          <div className="card-header-flex">
            <div className="pulse-col-title-wrap">
              <div className="pulse-col-icon red">
                <AlertOctagon size={18} />
              </div>
              <div>
                <h3 className="card-title">Live Threat Alerts</h3>
                <p className="card-subtitle">Correlated threat detections</p>
              </div>
            </div>
            <span className="badge badge-critical">{alerts.length} Active</span>
          </div>

          <div className="pulse-list">
            {alerts.map((alert, idx) => {
              const sev = (alert.severity || 'medium').toLowerCase();
              const badgeClass = sev === 'high' || sev === 'critical' ? 'badge-critical' : sev === 'medium' ? 'badge-high' : 'badge-low';

              return (
                <div key={idx} className="pulse-card">
                  <div className="pulse-card-top">
                    <span className="pulse-card-title">{alert.title}</span>
                    <span className={`badge ${badgeClass}`}>{alert.severity.toUpperCase()}</span>
                  </div>
                  <p className="pulse-card-desc">{alert.summary}</p>
                  <div className="pulse-card-footer">
                    <span className="mono text-muted">Source: <strong>{alert.source}</strong></span>
                    <span className="pulse-time-tag">
                      <Clock size={12} /> Real-time
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Column 2: Priority Incidents */}
        <div className="glass-panel pulse-column">
          <div className="card-header-flex">
            <div className="pulse-col-title-wrap">
              <div className="pulse-col-icon amber">
                <Flame size={18} />
              </div>
              <div>
                <h3 className="card-title">Priority Incidents</h3>
                <p className="card-subtitle">SOC queue scored by severity</p>
              </div>
            </div>
            <span className="badge badge-high">{incidents.length} In Queue</span>
          </div>

          <div className="pulse-list">
            {incidents.map((inc, idx) => {
              const isHigh = inc.score >= 80;
              const isMed = inc.score >= 50;
              const scoreColor = isHigh ? '#ef4444' : isMed ? '#f59e0b' : '#10b981';

              return (
                <div key={idx} className="incident-card">
                  <div className="incident-header">
                    <div>
                      <span className="incident-title">{inc.title}</span>
                      <div className="incident-meta-row">
                        <span className={`badge badge-${inc.severity === 'high' ? 'critical' : inc.severity === 'medium' ? 'high' : 'low'}`}>
                          {inc.severity.toUpperCase()}
                        </span>
                        <span className="incident-status-tag">Under Investigation</span>
                      </div>
                    </div>

                    <div className="incident-score-circle" style={{ borderColor: scoreColor, color: scoreColor }}>
                      <span className="score-num mono">{inc.score}</span>
                      <span className="score-lbl">RISK</span>
                    </div>
                  </div>

                  <div className="incident-progress-bar">
                    <div
                      className="incident-progress-fill"
                      style={{
                        width: `${inc.score}%`,
                        backgroundColor: scoreColor,
                      }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Column 3: Monitored Asset Health */}
        <div className="glass-panel pulse-column">
          <div className="card-header-flex">
            <div className="pulse-col-title-wrap">
              <div className="pulse-col-icon cyan">
                <Server size={18} />
              </div>
              <div>
                <h3 className="card-title">Asset Health Matrix</h3>
                <p className="card-subtitle">Critical node telemetry state</p>
              </div>
            </div>
            <span className="badge badge-cyan">{assets.length} Monitored</span>
          </div>

          <div className="pulse-list">
            {assets.map((asset, idx) => {
              const isCrit = asset.status === 'critical';
              const isWatch = asset.status === 'watch';

              const statusColor = isCrit ? '#ef4444' : isWatch ? '#f59e0b' : '#10b981';

              return (
                <div key={idx} className="asset-card">
                  <div className="asset-top">
                    <div className="asset-name-group">
                      <span className="pulse-dot" style={{ backgroundColor: statusColor, boxShadow: `0 0 8px ${statusColor}` }} />
                      <span className="asset-name mono">{asset.name}</span>
                    </div>
                    <span className={`badge badge-${isCrit ? 'critical' : isWatch ? 'high' : 'low'}`}>
                      {asset.status.toUpperCase()}
                    </span>
                  </div>

                  <div className="asset-footer">
                    <span className="asset-owner">Owner: <strong>{asset.owner}</strong></span>
                    <span className="asset-risk">Risk: <strong>{asset.risk.toUpperCase()}</strong></span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};
