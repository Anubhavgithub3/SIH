import React, { useState } from 'react';
import { PieChart, Shield } from 'lucide-react';
import type { NormalizedEvent } from '../types';

interface SeverityDonutChartProps {
  events: NormalizedEvent[];
}

export const SeverityDonutChart: React.FC<SeverityDonutChartProps> = ({ events }) => {
  const [hoveredSlice, setHoveredSlice] = useState<string | null>(null);

  const counts: Record<string, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  events.forEach((event) => {
    const rawSev = (event.event?.severity || 'low').toLowerCase();
    if (rawSev in counts) {
      counts[rawSev]++;
    } else if (rawSev.includes('crit')) {
      counts.critical++;
    } else if (rawSev.includes('warn') || rawSev.includes('med')) {
      counts.medium++;
    } else if (rawSev.includes('info')) {
      counts.info++;
    } else {
      counts.low++;
    }
  });

  const total = Math.max(1, events.length);

  const slices = [
    { label: 'Critical', key: 'critical', count: counts.critical, color: '#ef4444' },
    { label: 'High', key: 'high', count: counts.high, color: '#f97316' },
    { label: 'Medium', key: 'medium', count: counts.medium, color: '#f59e0b' },
    { label: 'Low', key: 'low', count: counts.low, color: '#10b981' },
    { label: 'Info', key: 'info', count: counts.info, color: '#3b82f6' },
  ].filter((s) => s.count > 0);

  const displaySlices = slices.length > 0 ? slices : [{ label: 'Normal', key: 'low', count: 1, color: '#10b981' }];
  const displayTotal = slices.length > 0 ? total : 1;

  let accumulatedAngle = 0;
  const radius = 64;
  const innerRadius = 44;
  const cx = 95;
  const cy = 95;

  const arcPaths = displaySlices.map((slice) => {
    const angle = (slice.count / displayTotal) * 360;
    const startAngle = accumulatedAngle;
    const endAngle = accumulatedAngle + angle;
    accumulatedAngle += angle;

    const startRad = ((startAngle - 90) * Math.PI) / 180;
    const endRad = ((endAngle - 90) * Math.PI) / 180;

    const x1Outer = cx + radius * Math.cos(startRad);
    const y1Outer = cy + radius * Math.sin(startRad);
    const x2Outer = cx + radius * Math.cos(endRad);
    const y2Outer = cy + radius * Math.sin(endRad);

    const x1Inner = cx + innerRadius * Math.cos(endRad);
    const y1Inner = cy + innerRadius * Math.sin(endRad);
    const x2Inner = cx + innerRadius * Math.cos(startRad);
    const y2Inner = cy + innerRadius * Math.sin(startRad);

    const largeArcFlag = angle > 180 ? 1 : 0;

    const pathData =
      angle >= 359.99
        ? `M ${cx} ${cy - radius} A ${radius} ${radius} 0 1 1 ${cx - 0.01} ${cy - radius} L ${cx - 0.01} ${cy - innerRadius} A ${innerRadius} ${innerRadius} 0 1 0 ${cx} ${cy - innerRadius} Z`
        : `M ${x1Outer} ${y1Outer} A ${radius} ${radius} 0 ${largeArcFlag} 1 ${x2Outer} ${y2Outer} L ${x1Inner} ${y1Inner} A ${innerRadius} ${innerRadius} 0 ${largeArcFlag} 0 ${x2Inner} ${y2Inner} Z`;

    const percentage = Math.round((slice.count / displayTotal) * 100);

    return {
      ...slice,
      pathData,
      percentage,
    };
  });

  return (
    <div className="donut-chart-card glass-panel">
      <div className="card-header-flex">
        <div>
          <h3 className="card-title">Severity Breakdown</h3>
          <p className="card-subtitle">Distribution of security event priorities</p>
        </div>
        <PieChart size={18} className="text-muted" />
      </div>

      <div className="donut-content-grid">
        <div className="donut-visual-wrap">
          <svg viewBox="0 0 190 190" className="donut-svg">
            {arcPaths.map((slice) => {
              const isHovered = hoveredSlice === slice.key;
              return (
                <path
                  key={slice.key}
                  d={slice.pathData}
                  fill={slice.color}
                  opacity={hoveredSlice && !isHovered ? 0.45 : 1}
                  stroke="#080e1a"
                  strokeWidth="2"
                  style={{
                    cursor: 'pointer',
                    transform: isHovered ? 'scale(1.04)' : 'scale(1)',
                    transformOrigin: `${cx}px ${cy}px`,
                    transition: 'transform 0.2s ease, opacity 0.2s ease',
                  }}
                  onMouseEnter={() => setHoveredSlice(slice.key)}
                  onMouseLeave={() => setHoveredSlice(null)}
                />
              );
            })}

            <circle cx={cx} cy={cy} r={innerRadius - 4} fill="#091224" />
            <text x={cx} y={cy - 2} textAnchor="middle" fill="#f1f5f9" className="donut-center-number">
              {hoveredSlice
                ? arcPaths.find((s) => s.key === hoveredSlice)?.count
                : events.length}
            </text>
            <text x={cx} y={cy + 14} textAnchor="middle" fill="#94a3b8" className="donut-center-label">
              {hoveredSlice
                ? arcPaths.find((s) => s.key === hoveredSlice)?.label.toUpperCase()
                : 'EVENTS'}
            </text>
          </svg>
        </div>

        <div className="donut-legend-list">
          {arcPaths.map((slice) => {
            const isHovered = hoveredSlice === slice.key;
            return (
              <div
                key={slice.key}
                className={`legend-row ${isHovered ? 'hovered' : ''}`}
                onMouseEnter={() => setHoveredSlice(slice.key)}
                onMouseLeave={() => setHoveredSlice(null)}
              >
                <div className="legend-info">
                  <span className="legend-dot" style={{ backgroundColor: slice.color }} />
                  <span className="legend-label">{slice.label}</span>
                </div>
                <div className="legend-numbers">
                  <span className="legend-count">{slice.count}</span>
                  <span className="legend-pct">({slice.percentage}%)</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      <div className="card-footer-flex">
        <Shield size={13} className="text-muted" />
        <span>Normalized with standard SIEM severity tiering</span>
      </div>
    </div>
  );
};
