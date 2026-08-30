import React from 'react';
import {
  FileText,
  ShieldAlert,
  Slash,
  Layers,
  AlertTriangle,
  RadioTower,
} from 'lucide-react';
import type { SecuritySummary, MLInsights } from '../types';

interface MetricsCardsProps {
  summary: SecuritySummary | null;
  mlInsights: MLInsights | null;
  eventCount: number;
}

export const MetricsCards: React.FC<MetricsCardsProps> = ({
  summary,
  mlInsights,
  eventCount,
}) => {
  const totalEvents = summary?.total_events ?? eventCount;
  const anomalyScore = Math.round((mlInsights?.anomaly_score ?? summary?.ml_anomaly_score ?? 0) * 100);
  const threatLabel = mlInsights?.threat_label ?? summary?.ml_threat_label ?? 'benign';
  const blockedCount = summary?.blocked_events ?? 0;
  const sourceCount = (summary?.sources ?? []).length || 3;
  const highSeverityCount = summary?.high_severity ?? 0;
  const suspiciousIpCount = (summary?.suspicious_ips ?? []).length;

  const getThreatBadgeClass = (label: string) => {
    switch (label.toLowerCase()) {
      case 'critical':
        return 'badge-critical';
      case 'suspicious':
        return 'badge-high';
      case 'monitor':
        return 'badge-medium';
      default:
        return 'badge-low';
    }
  };

  return (
    <div className="metrics-grid">
      {/* Total Ingested */}
      <div className="metric-card glass-panel">
        <div className="metric-header">
          <span className="metric-title">Logs Ingested</span>
          <div className="metric-icon-box bg-blue">
            <FileText size={18} />
          </div>
        </div>
        <div className="metric-value-row">
          <span className="metric-value">{totalEvents}</span>
          <span className="metric-subtext">Events in memory</span>
        </div>
        <div className="metric-footer">
          <span className="footer-tag">Live Pipeline</span>
          <span className="footer-info">Validated Schema</span>
        </div>
      </div>

      {/* ML Risk Posture */}
      <div className="metric-card glass-panel">
        <div className="metric-header">
          <span className="metric-title">ML Anomaly Score</span>
          <div className="metric-icon-box bg-purple">
            <ShieldAlert size={18} />
          </div>
        </div>
        <div className="metric-value-row">
          <span className="metric-value">{anomalyScore}%</span>
          <span className={`badge ${getThreatBadgeClass(threatLabel)}`}>
            {threatLabel}
          </span>
        </div>
        <div className="metric-footer">
          <span className="footer-tag">Random Forest</span>
          <span className="footer-info">Multi-factor inference</span>
        </div>
      </div>

      {/* Blocked / Denied */}
      <div className="metric-card glass-panel">
        <div className="metric-header">
          <span className="metric-title">Blocked Events</span>
          <div className="metric-icon-box bg-amber">
            <Slash size={18} />
          </div>
        </div>
        <div className="metric-value-row">
          <span className="metric-value">{blockedCount}</span>
          <span className="metric-subtext">Deny / Drop actions</span>
        </div>
        <div className="metric-footer">
          <span className="footer-tag">Enforced</span>
          <span className="footer-info">Perimeter Filter</span>
        </div>
      </div>

      {/* Monitored Sources */}
      <div className="metric-card glass-panel">
        <div className="metric-header">
          <span className="metric-title">Active Sources</span>
          <div className="metric-icon-box bg-cyan">
            <Layers size={18} />
          </div>
        </div>
        <div className="metric-value-row">
          <span className="metric-value">{sourceCount}</span>
          <span className="metric-subtext">Heterogeneous types</span>
        </div>
        <div className="metric-footer">
          <span className="footer-tag">Multi-Vendor</span>
          <span className="footer-info">Syslog, CEF, JSON, LEEF</span>
        </div>
      </div>

      {/* High / Critical Severity */}
      <div className="metric-card glass-panel">
        <div className="metric-header">
          <span className="metric-title">Elevated Severity</span>
          <div className="metric-icon-box bg-red">
            <AlertTriangle size={18} />
          </div>
        </div>
        <div className="metric-value-row">
          <span className="metric-value">{highSeverityCount}</span>
          <span className="metric-subtext">High & Critical</span>
        </div>
        <div className="metric-footer">
          <span className="footer-tag">Urgent Triage</span>
          <span className="footer-info">Requires Attention</span>
        </div>
      </div>

      {/* Suspicious Remote IPs */}
      <div className="metric-card glass-panel">
        <div className="metric-header">
          <span className="metric-title">Threat Intel Matches</span>
          <div className="metric-icon-box bg-emerald">
            <RadioTower size={18} />
          </div>
        </div>
        <div className="metric-value-row">
          <span className="metric-value">{suspiciousIpCount}</span>
          <span className="metric-subtext">Suspicious / Malicious</span>
        </div>
        <div className="metric-footer">
          <span className="footer-tag">IP Intelligence</span>
          <span className="footer-info">GeoIP & Reputation</span>
        </div>
      </div>
    </div>
  );
};
