import React from 'react';
import { ShieldAlert, Cpu, AlertCircle } from 'lucide-react';
import type { MLInsights } from '../types';

interface ThreatRiskGaugeProps {
  mlInsights: MLInsights | null;
}

export const ThreatRiskGauge: React.FC<ThreatRiskGaugeProps> = ({ mlInsights }) => {
  const score = mlInsights?.anomaly_score ?? 0;
  const percentage = Math.round(score * 100);
  const label = mlInsights?.threat_label ?? 'benign';
  const totalEvaluated = mlInsights?.total_evaluated ?? 0;

  const radius = 78;
  const strokeWidth = 14;
  const circumference = Math.PI * radius * 1.5;
  const strokeDashoffset = circumference - (percentage / 100) * circumference;

  const getColor = (pct: number) => {
    if (pct >= 80) return { stroke: '#ef4444', glow: 'rgba(239, 68, 68, 0.4)', text: '#f87171' };
    if (pct >= 60) return { stroke: '#F29F67', glow: 'rgba(242, 159, 103, 0.4)', text: '#F29F67' };
    if (pct >= 35) return { stroke: '#E0B50F', glow: 'rgba(224, 181, 15, 0.4)', text: '#E0B50F' };
    return { stroke: '#34B1AA', glow: 'rgba(52, 177, 170, 0.4)', text: '#34B1AA' };
  };

  const theme = getColor(percentage);

  return (
    <div className="gauge-container glass-panel">
      <div className="card-header-flex">
        <div>
          <h3 className="card-title">ML Threat Posture</h3>
          <p className="card-subtitle">Real-time anomaly scoring via Random Forest</p>
        </div>
        <div className="chip-model">
          <Cpu size={14} />
          <span>RF-v1.4</span>
        </div>
      </div>

      <div className="gauge-visual-wrap">
        <svg className="gauge-svg" viewBox="0 0 200 160">
          <defs>
            <linearGradient id="gaugeGradient" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#34B1AA" />
              <stop offset="40%" stopColor="#E0B50F" />
              <stop offset="75%" stopColor="#F29F67" />
              <stop offset="100%" stopColor="#ef4444" />
            </linearGradient>
            <filter id="gaugeGlow">
              <feGaussianBlur stdDeviation="3.5" result="coloredBlur" />
              <feMerge>
                <feMergeNode in="coloredBlur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          {/* Background Track Arc */}
          <path
            d="M 30 140 A 78 78 0 1 1 170 140"
            fill="none"
            stroke="rgba(30, 48, 86, 0.6)"
            strokeWidth={strokeWidth}
            strokeLinecap="round"
          />

          {/* Active Colored Arc */}
          <path
            d="M 30 140 A 78 78 0 1 1 170 140"
            fill="none"
            stroke={theme.stroke}
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            filter="url(#gaugeGlow)"
            style={{ transition: 'stroke-dashoffset 0.8s cubic-bezier(0.4, 0, 0.2, 1), stroke 0.5s ease' }}
          />

          {/* Gauge Center Text */}
          <text x="100" y="98" textAnchor="middle" className="gauge-value-text" fill={theme.text}>
            {percentage}%
          </text>
          <text x="100" y="122" textAnchor="middle" className="gauge-label-text" fill="#94a3b8">
            ANOMALY PROBABILITY
          </text>
        </svg>

        <div className="gauge-verdict-box">
          <div className="verdict-row">
            <span className="verdict-title">Verdict:</span>
            <span className="verdict-badge" style={{ backgroundColor: `${theme.stroke}22`, color: theme.text, borderColor: theme.stroke }}>
              <ShieldAlert size={14} />
              {label.toUpperCase()}
            </span>
          </div>
          <div className="verdict-meta">
            <span>Evaluated: <strong>{totalEvaluated} events</strong></span>
            <span>Confidence: <strong>{percentage > 70 ? 'High (94%)' : percentage > 40 ? 'Moderate (82%)' : 'Nominal'}</strong></span>
          </div>
        </div>
      </div>

      <div className="gauge-footer-note">
        <AlertCircle size={14} className="note-icon" />
        <span>Synthesized across severity, geo-risk, deny triggers, and threat intelligence.</span>
      </div>
    </div>
  );
};
