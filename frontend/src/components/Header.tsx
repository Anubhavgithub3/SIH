import React from 'react';
import {
  Shield,
  RefreshCw,
  Trash2,
  Home,
  LayoutDashboard,
  FileCode2,
  Database,
  Radio,
  Cpu,
  BookOpen,
  Sun,
  Moon,
  Sparkles,
} from 'lucide-react';
import type { HealthStatus, ThemeMode } from '../types';

interface HeaderProps {
  currentView: string;
  setCurrentView: (view: string) => void;
  health: HealthStatus | null;
  latencyMs: number | null;
  isRefreshing: boolean;
  onRefresh: () => void;
  autoRefreshInterval: number;
  setAutoRefreshInterval: (sec: number) => void;
  onClearEvents: () => void;
  eventCount: number;
  theme: ThemeMode;
  setTheme: (theme: ThemeMode) => void;
}

export const Header: React.FC<HeaderProps> = ({
  currentView,
  setCurrentView,
  health,
  latencyMs,
  isRefreshing,
  onRefresh,
  autoRefreshInterval,
  setAutoRefreshInterval,
  onClearEvents,
  eventCount,
  theme,
  setTheme,
}) => {
  const isOnline = !!health;

  const topNavTabs = [
    { id: 'landing', label: 'Home', icon: Home },
    { id: 'analytics', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'ingest', label: 'Pipeline Studio', icon: FileCode2 },
    { id: 'events', label: 'SIEM Explorer', icon: Database, badge: eventCount },
    { id: 'pulse', label: 'Security Pulse', icon: Radio },
    { id: 'ml', label: 'ML Engine', icon: Cpu },
    { id: 'api-docs', label: 'API Docs', icon: BookOpen },
  ];

  return (
    <header className="header-bar">
      <div className="header-top">
        <div className="brand-section" onClick={() => setCurrentView('landing')} style={{ cursor: 'pointer' }}>
          <div className="brand-icon-wrapper">
            <Shield className="brand-shield" size={22} />
          </div>
          <div>
            <div className="brand-title">UNIVERSAL LOG FRAMEWORK</div>
            <div className="brand-subtitle">Heterogeneous Log Normalization • Threat Intel • ML Anomaly Engine</div>
          </div>
        </div>

        <div className="header-actions">
          {/* Health & Latency Badge */}
          <div className={`status-pill ${isOnline ? 'status-online' : 'status-offline'}`}>
            <span className={`pulse-dot ${isOnline ? 'online' : 'critical'}`} />
            <span className="status-text">{isOnline ? 'CORE ONLINE' : 'BACKEND DISCONNECTED'}</span>
            {latencyMs !== null && isOnline && (
              <span className="latency-text">{latencyMs}ms</span>
            )}
          </div>

          {/* Theme Mode Switcher (Light / Dark / Color) */}
          <div className="theme-switch-group">
            <button
              onClick={() => setTheme('light')}
              className={`theme-switch-btn ${theme === 'light' ? 'active' : ''}`}
              title="White / Light Mode"
            >
              <Sun size={13} />
              <span>Light</span>
            </button>
            <button
              onClick={() => setTheme('dark')}
              className={`theme-switch-btn ${theme === 'dark' ? 'active' : ''}`}
              title="Dark Mode"
            >
              <Moon size={13} />
              <span>Dark</span>
            </button>
            <button
              onClick={() => setTheme('cyber')}
              className={`theme-switch-btn ${theme === 'cyber' ? 'active' : ''}`}
              title="Cyber / Color Mode"
            >
              <Sparkles size={13} />
              <span>Color</span>
            </button>
          </div>

          {/* Auto Refresh Select */}
          <div className="auto-refresh-selector">
            <span className="auto-refresh-label">Poll:</span>
            <select
              value={autoRefreshInterval}
              onChange={(e) => setAutoRefreshInterval(Number(e.target.value))}
              className="refresh-select"
              title="Auto-refresh interval"
            >
              <option value={3}>3s</option>
              <option value={5}>5s</option>
              <option value={10}>10s</option>
              <option value={0}>Pause</option>
            </select>
          </div>

          {/* Manual Refresh Button */}
          <button
            onClick={onRefresh}
            className="btn btn-secondary btn-sm refresh-btn"
            title="Refresh dashboard data"
            disabled={isRefreshing}
          >
            <RefreshCw size={13} className={isRefreshing ? 'spin' : ''} />
            <span>Sync</span>
          </button>

          {/* Clear / Reset button */}
          <button
            onClick={onClearEvents}
            className="btn btn-danger btn-sm"
            title="Reset event buffer"
          >
            <Trash2 size={13} />
            <span>Reset</span>
          </button>
        </div>
      </div>

      {/* Top Navigation Tabs */}
      <nav className="tab-navigation">
        {topNavTabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = currentView === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setCurrentView(tab.id)}
              className={`nav-tab-button ${isActive ? 'active' : ''}`}
            >
              <Icon size={16} />
              <span>{tab.label}</span>
              {typeof tab.badge === 'number' && (
                <span className="tab-counter mono">{tab.badge}</span>
              )}
            </button>
          );
        })}
      </nav>
    </header>
  );
};
