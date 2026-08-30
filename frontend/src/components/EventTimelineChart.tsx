import React, { useState } from 'react';
import { TrendingUp, Clock } from 'lucide-react';
import type { NormalizedEvent } from '../types';

interface EventTimelineChartProps {
  events: NormalizedEvent[];
}

export const EventTimelineChart: React.FC<EventTimelineChartProps> = ({ events }) => {
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);

  const eventList = events.slice(0, 15).reverse();
  const maxEvents = Math.max(1, eventList.length);

  const points = eventList.map((event, idx) => {
    const severity = (event.event?.severity || 'low').toLowerCase();
    const isHigh = severity === 'critical' || severity === 'high';
    const isMedium = severity === 'medium';
    const threatScore = isHigh ? 85 : isMedium ? 50 : 20;

    return {
      index: idx,
      timestamp: event.timestamp || `T-${15 - idx}m`,
      source: event.source || 'unknown',
      action: event.event?.action || 'unknown',
      severity,
      threatScore,
      ip: event.network?.source_ip || event.network?.destination_ip || 'local',
      threat: event.threat?.reputation || 'unknown',
    };
  });

  const width = 580;
  const height = 180;
  const paddingX = 30;
  const paddingY = 25;
  const usableWidth = width - paddingX * 2;
  const usableHeight = height - paddingY * 2;

  const getX = (idx: number) => {
    if (points.length <= 1) return width / 2;
    return paddingX + (idx / (points.length - 1)) * usableWidth;
  };

  const getY = (score: number) => {
    return height - paddingY - (score / 100) * usableHeight;
  };

  const pathD = points.length > 0 ? points.reduce((acc, pt, idx) => {
    const x = getX(idx);
    const y = getY(pt.threatScore);
    if (idx === 0) return `M ${x} ${y}`;
    const prevX = getX(idx - 1);
    const prevY = getY(points[idx - 1].threatScore);
    const cpX1 = prevX + (x - prevX) / 2;
    const cpX2 = cpX1;
    return `${acc} C ${cpX1} ${prevY}, ${cpX2} ${y}, ${x} ${y}`;
  }, '') : '';

  const areaD = points.length > 0
    ? `${pathD} L ${getX(points.length - 1)} ${height - paddingY} L ${getX(0)} ${height - paddingY} Z`
    : '';

  return (
    <div className="timeline-chart-card glass-panel">
      <div className="card-header-flex">
        <div>
          <h3 className="card-title">Telemetry Threat Velocity</h3>
          <p className="card-subtitle">Severity & threat pulse over sequential log stream</p>
        </div>
        <div className="chart-legend-row">
          <span className="legend-item"><span className="legend-dot red" />Critical/High</span>
          <span className="legend-item"><span className="legend-dot amber" />Medium</span>
          <span className="legend-item"><span className="legend-dot green" />Low/Benign</span>
        </div>
      </div>

      <div className="chart-wrapper">
        <svg
          viewBox={`0 0 ${width} ${height}`}
          className="timeline-svg"
          onMouseLeave={() => setHoveredIndex(null)}
        >
          <defs>
            <linearGradient id="areaGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#F29F67" stopOpacity="0.4" />
              <stop offset="60%" stopColor="#F29F67" stopOpacity="0.1" />
              <stop offset="100%" stopColor="#F29F67" stopOpacity="0.0" />
            </linearGradient>
            <linearGradient id="strokeGradient" x1="0" y1="0" x2="1" y2="0">
              <stop offset="0%" stopColor="#34B1AA" />
              <stop offset="50%" stopColor="#F29F67" />
              <stop offset="100%" stopColor="#ef4444" />
            </linearGradient>
          </defs>

          {/* Grid lines */}
          <line x1={paddingX} y1={getY(25)} x2={width - paddingX} y2={getY(25)} stroke="rgba(255, 255, 255, 0.07)" strokeDasharray="4 4" />
          <line x1={paddingX} y1={getY(50)} x2={width - paddingX} y2={getY(50)} stroke="rgba(255, 255, 255, 0.07)" strokeDasharray="4 4" />
          <line x1={paddingX} y1={getY(75)} x2={width - paddingX} y2={getY(75)} stroke="rgba(255, 255, 255, 0.07)" strokeDasharray="4 4" />

          {/* Area fill */}
          {points.length > 0 && (
            <path d={areaD} fill="url(#areaGradient)" />
          )}

          {/* Line curve */}
          {points.length > 0 && (
            <path
              d={pathD}
              fill="none"
              stroke="url(#strokeGradient)"
              strokeWidth="3.5"
              strokeLinecap="round"
            />
          )}

          {/* Data Points */}
          {points.map((pt, idx) => {
            const cx = getX(idx);
            const cy = getY(pt.threatScore);
            const isHovered = hoveredIndex === idx;
            const ptColor = pt.threatScore > 70 ? '#ef4444' : pt.threatScore > 40 ? '#E0B50F' : '#34B1AA';

            return (
              <g key={idx}>
                {isHovered && (
                  <line
                    x1={cx}
                    y1={paddingY}
                    x2={cx}
                    y2={height - paddingY}
                    stroke="rgba(242, 159, 103, 0.6)"
                    strokeWidth="1.5"
                    strokeDasharray="3 3"
                  />
                )}
                <circle
                  cx={cx}
                  cy={cy}
                  r={isHovered ? 7 : 4.5}
                  fill={ptColor}
                  stroke="#1E1E2C"
                  strokeWidth="2"
                  style={{ cursor: 'pointer', transition: 'r 0.15s ease' }}
                  onMouseEnter={() => setHoveredIndex(idx)}
                />
              </g>
            );
          })}
        </svg>

        {hoveredIndex !== null && points[hoveredIndex] && (
          <div
            className="chart-tooltip glass-panel"
            style={{
              left: `${Math.min(85, Math.max(15, (getX(hoveredIndex) / width) * 100))}%`,
              top: '10px',
            }}
          >
            <div className="tooltip-header">
              <span className="mono">{points[hoveredIndex].timestamp}</span>
              <span className={`badge badge-${points[hoveredIndex].severity}`}>
                {points[hoveredIndex].severity}
              </span>
            </div>
            <div className="tooltip-body">
              <div>Source: <strong>{points[hoveredIndex].source}</strong></div>
              <div>Action: <strong>{points[hoveredIndex].action}</strong></div>
              <div>IP: <span className="mono">{points[hoveredIndex].ip}</span></div>
              <div>Threat Intel: <strong>{points[hoveredIndex].threat}</strong></div>
            </div>
          </div>
        )}
      </div>

      <div className="chart-bottom-bar">
        <div className="status-label-wrap">
          <Clock size={13} />
          <span>Tracking continuous stream of latest {maxEvents} log entries</span>
        </div>
        <div className="status-trend-wrap">
          <TrendingUp size={13} />
          <span>Automated pipeline normalization active</span>
        </div>
      </div>
    </div>
  );
};
