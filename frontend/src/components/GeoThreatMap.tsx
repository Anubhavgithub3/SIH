import React from 'react';
import { Globe2, ShieldAlert } from 'lucide-react';
import type { NormalizedEvent } from '../types';

interface GeoThreatMapProps {
  events: NormalizedEvent[];
}

export const GeoThreatMap: React.FC<GeoThreatMapProps> = ({ events }) => {
  const geoCounts: Record<string, { count: number; malicious: number; suspicious: number; benign: number }> = {};

  events.forEach((e) => {
    const country = (e.enrichment?.country || 'UNKNOWN').toUpperCase();
    if (!geoCounts[country]) {
      geoCounts[country] = { count: 0, malicious: 0, suspicious: 0, benign: 0 };
    }
    geoCounts[country].count++;

    const rep = (e.threat?.reputation || 'unknown').toLowerCase();
    if (rep === 'malicious') geoCounts[country].malicious++;
    else if (rep === 'suspicious') geoCounts[country].suspicious++;
    else if (rep === 'benign') geoCounts[country].benign++;
  });

  const getCountryDetails = (code: string) => {
    switch (code) {
      case 'CN':
        return { name: 'China', flag: '🇨🇳', baseRisk: 'High Risk Region', riskScore: 88, color: '#ef4444' };
      case 'RU':
        return { name: 'Russian Federation', flag: '🇷🇺', baseRisk: 'Elevated Threat', riskScore: 82, color: '#f97316' };
      case 'IR':
        return { name: 'Iran', flag: '🇮🇷', baseRisk: 'High Risk Region', riskScore: 80, color: '#f97316' };
      case 'US':
        return { name: 'United States', flag: '🇺🇸', baseRisk: 'Standard Traffic', riskScore: 24, color: '#3b82f6' };
      case 'IN':
        return { name: 'India', flag: '🇮🇳', baseRisk: 'Internal / Regional', riskScore: 30, color: '#10b981' };
      case 'DE':
        return { name: 'Germany', flag: '🇩🇪', baseRisk: 'EU Traffic', riskScore: 22, color: '#06b6d4' };
      case 'GB':
        return { name: 'United Kingdom', flag: '🇬🇧', baseRisk: 'Standard', riskScore: 20, color: '#06b6d4' };
      default:
        return { name: code === 'UNKNOWN' ? 'Unmapped Subnet' : code, flag: '🌐', baseRisk: 'Unclassified', riskScore: 35, color: '#64748b' };
    }
  };

  const countries = Object.entries(geoCounts)
    .sort((a, b) => b[1].count - a[1].count)
    .map(([code, stats]) => {
      const details = getCountryDetails(code);
      return {
        code,
        stats,
        ...details,
      };
    });

  return (
    <div className="geo-threat-card glass-panel">
      <div className="card-header-flex">
        <div>
          <h3 className="card-title">GeoIP Threat Origins</h3>
          <p className="card-subtitle">Geographic risk distribution enriched via IP telemetry</p>
        </div>
        <div className="geo-globe-icon">
          <Globe2 size={20} className="text-accent" />
        </div>
      </div>

      <div className="geo-list">
        {countries.map((c) => {
          const hasThreats = c.stats.malicious > 0 || c.stats.suspicious > 0;
          return (
            <div key={c.code} className="geo-item">
              <div className="geo-item-top">
                <div className="geo-name-col">
                  <span className="geo-flag">{c.flag}</span>
                  <div className="geo-title-box">
                    <span className="geo-country-name">{c.name}</span>
                    <span className="geo-code-badge mono">{c.code}</span>
                  </div>
                </div>

                <div className="geo-metrics-col">
                  <div className="geo-event-counter">
                    <strong>{c.stats.count}</strong> events
                  </div>
                  {hasThreats ? (
                    <span className="badge badge-critical">
                      <ShieldAlert size={12} />
                      {c.stats.suspicious + c.stats.malicious} Flagged
                    </span>
                  ) : (
                    <span className="badge badge-low">Benign</span>
                  )}
                </div>
              </div>

              {/* Threat Risk Meter */}
              <div className="geo-risk-bar-wrap">
                <div className="geo-risk-labels">
                  <span className="geo-risk-status">{c.baseRisk}</span>
                  <span className="geo-risk-val mono">Risk {c.riskScore}/100</span>
                </div>
                <div className="geo-bar-track">
                  <div
                    className="geo-bar-fill"
                    style={{
                      width: `${c.riskScore}%`,
                      backgroundColor: c.color,
                    }}
                  />
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
