import React from 'react';
import {
  AlertOctagon,
  Flame,
  Server,
  Clock,
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
  return (
    <div className="security-pulse-container">
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
                    <span className={`badge ${badgeClass}`}>{alert.severity}</span>
                  </div>
                  <p className="pulse-card-desc">{alert.summary}</p>
                  <div className="pulse-card-footer">
                    <span className="mono text-muted">Source: {alert.source}</span>
                    <span className="pulse-time-tag">
                      <Clock size={11} /> Real-time
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
                          {inc.severity}
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
                      {asset.status}
                    </span>
                  </div>

                  <div className="asset-footer">
                    <span className="asset-owner">Owner: <strong>{asset.owner}</strong></span>
                    <span className="asset-risk">Risk: <strong>{asset.risk}</strong></span>
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
