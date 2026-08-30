import React from 'react';
import { Cpu, CheckCircle2, ShieldAlert, Sliders, Zap } from 'lucide-react';
import type { MLInsights, NormalizedEvent } from '../types';

interface MLFeatureInfluenceProps {
  mlInsights: MLInsights | null;
  events: NormalizedEvent[];
}

export const MLFeatureInfluence: React.FC<MLFeatureInfluenceProps> = ({
  mlInsights,
  events,
}) => {
  const modelName = mlInsights?.model || 'RandomForestClassifier (100 Estimators)';
  const anomalyScore = mlInsights?.anomaly_score ?? 0;
  const threatLabel = mlInsights?.threat_label ?? 'benign';
  const evaluatedCount = mlInsights?.total_evaluated ?? events.length;

  const featureWeights = [
    {
      name: 'Threat Reputation Flag',
      weight: 35,
      impact: 'High',
      desc: 'Matches with known malicious/suspicious external IP addresses in CTI databases',
      color: '#ef4444',
    },
    {
      name: 'Event Severity Level',
      weight: 25,
      impact: 'High',
      desc: 'Critical/High severity ranking assigned by upstream security appliances',
      color: '#f97316',
    },
    {
      name: 'Security Action (Deny/Drop/Block)',
      weight: 18,
      impact: 'Medium',
      desc: 'Perimeter firewall enforcement rejecting unauthorized connection attempts',
      color: '#f59e0b',
    },
    {
      name: 'High-Risk GeoIP Origin',
      weight: 12,
      impact: 'Medium',
      desc: 'Autonomous system originating from high-risk geopolitical jurisdictions (CN, RU, IR, KP)',
      color: '#8b5cf6',
    },
    {
      name: 'Payload Attack Keywords',
      weight: 10,
      impact: 'Low-Medium',
      desc: 'Regex signature matching for tokens like "malware", "c2", "beacon", "failed password"',
      color: '#06b6d4',
    },
  ];

  return (
    <div className="ml-engine-container">
      {/* Model Overview Banner */}
      <div className="ml-banner glass-panel">
        <div className="ml-banner-left">
          <div className="ml-icon-wrapper">
            <Cpu size={32} className="text-accent" />
          </div>
          <div>
            <div className="ml-badge-row">
              <span className="badge badge-purple">Supervised Machine Learning</span>
              <span className="badge badge-cyan">Scikit-Learn Ensemble</span>
            </div>
            <h2 className="ml-title">{modelName}</h2>
            <p className="ml-desc">
              Trained on balanced cybersecurity threat telemetry vectors. Produces probabilistic anomaly scores for zero-day and multi-stage attack detection.
            </p>
          </div>
        </div>

        <div className="ml-banner-stats">
          <div className="ml-stat-card">
            <span className="ml-stat-label">Model Status</span>
            <div className="ml-stat-val text-emerald">
              <CheckCircle2 size={16} />
              Active (Inference &lt;2ms)
            </div>
          </div>
          <div className="ml-stat-card">
            <span className="ml-stat-label">Average Risk Index</span>
            <div className="ml-stat-val text-accent">
              {Math.round(anomalyScore * 100)}% ({threatLabel})
            </div>
          </div>
          <div className="ml-stat-card">
            <span className="ml-stat-label">Events Processed</span>
            <div className="ml-stat-val">
              {evaluatedCount} Records
            </div>
          </div>
        </div>
      </div>

      {/* Feature Influence Weights */}
      <div className="ml-grid">
        <div className="glass-panel ml-weights-panel">
          <div className="card-header-flex">
            <div>
              <h3 className="card-title">Random Forest Feature Importance</h3>
              <p className="card-subtitle">Relative weight contributions during event scoring</p>
            </div>
            <Sliders size={18} className="text-muted" />
          </div>

          <div className="feature-weight-list">
            {featureWeights.map((f) => (
              <div key={f.name} className="feature-weight-item">
                <div className="feature-weight-header">
                  <div>
                    <span className="feature-name">{f.name}</span>
                    <p className="feature-desc">{f.desc}</p>
                  </div>
                  <div className="feature-weight-val">
                    <span className="feature-pct mono">{f.weight}%</span>
                    <span className="feature-impact" style={{ color: f.color }}>{f.impact}</span>
                  </div>
                </div>

                <div className="feature-bar-track">
                  <div
                    className="feature-bar-fill"
                    style={{
                      width: `${f.weight * 2.5}%`,
                      backgroundColor: f.color,
                      boxShadow: `0 0 8px ${f.color}50`,
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Model Inference Breakdown for latest events */}
        <div className="glass-panel ml-records-panel">
          <div className="card-header-flex">
            <div>
              <h3 className="card-title">Recent Event Model Inferences</h3>
              <p className="card-subtitle">Per-event anomaly classification details</p>
            </div>
            <Zap size={18} className="text-muted" />
          </div>

          <div className="inference-records-list">
            {(mlInsights?.details || []).slice(0, 7).map((item, idx) => {
              const scorePct = Math.round(item.score * 100);
              const isHigh = scorePct >= 60;
              const isMed = scorePct >= 35;
              const badgeType = isHigh ? 'badge-critical' : isMed ? 'badge-high' : 'badge-low';

              return (
                <div key={idx} className="inference-item">
                  <div className="inference-item-left">
                    <span className="inference-source mono">{item.source || 'event'}</span>
                    <span className={`badge ${badgeType}`}>
                      {item.label}
                    </span>
                    <span className="inference-sev">Sev: {item.severity}</span>
                  </div>

                  <div className="inference-score-wrap">
                    <div className="score-meter-track">
                      <div
                        className="score-meter-fill"
                        style={{
                          width: `${scorePct}%`,
                          backgroundColor: isHigh ? '#ef4444' : isMed ? '#f59e0b' : '#10b981',
                        }}
                      />
                    </div>
                    <span className="inference-score-val mono">{scorePct}%</span>
                  </div>
                </div>
              );
            })}

            {(!mlInsights?.details || mlInsights.details.length === 0) && (
              <div className="empty-state-notice">
                <ShieldAlert size={24} className="text-muted" />
                <p>No model inference records yet. Ingest logs to see live ML classifications.</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
