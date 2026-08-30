import React from 'react';
import { Server, HardDrive, Terminal, Globe, Cloud } from 'lucide-react';
import type { NormalizedEvent } from '../types';

interface SourcesBarChartProps {
  events: NormalizedEvent[];
}

export const SourcesBarChart: React.FC<SourcesBarChartProps> = ({ events }) => {
  const sourceCounts: Record<string, number> = {};

  events.forEach((e) => {
    const src = (e.source || 'unknown').toLowerCase();
    sourceCounts[src] = (sourceCounts[src] || 0) + 1;
  });

  const total = Math.max(1, events.length);

  const getSourceMeta = (src: string) => {
    switch (src) {
      case 'firewall':
        return { name: 'Firewall Perimeter', icon: HardDrive, color: '#3b82f6', format: 'CEF / Key-Value' };
      case 'linux':
        return { name: 'Linux Syslog', icon: Terminal, color: '#10b981', format: 'RFC3164 Syslog' };
      case 'api':
        return { name: 'API Gateway / Cloud', icon: Cloud, color: '#8b5cf6', format: 'JSON / REST' };
      case 'palo alto':
      case 'paloalto':
        return { name: 'Palo Alto Networks', icon: Server, color: '#f59e0b', format: 'CEF Log' };
      case 'qradar':
        return { name: 'IBM QRadar SIEM', icon: Globe, color: '#06b6d4', format: 'LEEF Payload' };
      default:
        return { name: src.toUpperCase(), icon: Server, color: '#64748b', format: 'Generic Log' };
    }
  };

  const sources = Object.entries(sourceCounts)
    .sort((a, b) => b[1] - a[1])
    .map(([key, count]) => {
      const meta = getSourceMeta(key);
      const percentage = Math.round((count / total) * 100);
      return {
        key,
        count,
        percentage,
        ...meta,
      };
    });

  return (
    <div className="sources-bar-card glass-panel">
      <div className="card-header-flex">
        <div>
          <h3 className="card-title">Telemetry Ingestion Sources</h3>
          <p className="card-subtitle">Multi-vendor format distribution and parsing volume</p>
        </div>
        <div className="badge badge-info">
          {sources.length} Active Feeds
        </div>
      </div>

      <div className="sources-list">
        {sources.map((src) => {
          const Icon = src.icon;
          return (
            <div key={src.key} className="source-item">
              <div className="source-item-header">
                <div className="source-name-wrap">
                  <div className="source-icon" style={{ color: src.color, backgroundColor: `${src.color}18` }}>
                    <Icon size={14} />
                  </div>
                  <span className="source-title">{src.name}</span>
                  <span className="source-format-pill">{src.format}</span>
                </div>
                <div className="source-stats">
                  <span className="source-count">{src.count} events</span>
                  <span className="source-pct">{src.percentage}%</span>
                </div>
              </div>

              <div className="source-progress-track">
                <div
                  className="source-progress-fill"
                  style={{
                    width: `${src.percentage}%`,
                    backgroundColor: src.color,
                    boxShadow: `0 0 10px ${src.color}40`,
                  }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
