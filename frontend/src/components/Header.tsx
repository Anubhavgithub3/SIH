import React, { useState } from 'react';
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
  Settings2,
  X,
  CheckCircle2,
  AlertCircle,
} from 'lucide-react';
import type { HealthStatus, ThemeMode } from '../types';
import { getApiBase, setApiBase } from '../api';

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
  const [showConfigModal, setShowConfigModal] = useState(false);
  const [apiUrlInput, setApiUrlInput] = useState(getApiBase());

  const topNavTabs = [
    { id: 'landing', label: 'Home', icon: Home },
    { id: 'analytics', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'ingest', label: 'Pipeline Studio', icon: FileCode2 },
    { id: 'events', label: 'SIEM Explorer', icon: Database, badge: eventCount },
    { id: 'pulse', label: 'Security Pulse', icon: Radio },
    { id: 'ml', label: 'ML Engine', icon: Cpu },
    { id: 'api-docs', label: 'API Docs', icon: BookOpen },
  ];

  const handleSaveApiUrl = () => {
    setApiBase(apiUrlInput);
    setShowConfigModal(false);
    onRefresh();
  };

  const handleResetToDefault = () => {
    setApiUrlInput('');
    setApiBase('');
    setShowConfigModal(false);
    onRefresh();
  };

  return (
    <>
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
            {/* Health & Latency Badge - Clickable to open config */}
            <div
              className={`status-pill ${isOnline ? 'status-online' : 'status-offline'}`}
              onClick={() => setShowConfigModal(true)}
              style={{ cursor: 'pointer' }}
              title="Click to configure backend API endpoint"
            >
              <span className={`pulse-dot ${isOnline ? 'online' : 'critical'}`} />
              <span className="status-text">{isOnline ? 'CORE ONLINE' : 'BACKEND DISCONNECTED'}</span>
              {latencyMs !== null && isOnline && (
                <span className="latency-text">{latencyMs}ms</span>
              )}
              <Settings2 size={12} style={{ opacity: 0.7 }} />
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

      {/* Backend Connection Modal */}
      {showConfigModal && (
        <div className="modal-backdrop" onClick={() => setShowConfigModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '540px' }}>
            <div className="card-header-flex">
              <div>
                <h3 className="modal-title">Backend API Connection</h3>
                <p className="card-subtitle">Configure the FastAPI backend server URL for live telemetry</p>
              </div>
              <button onClick={() => setShowConfigModal(false)} className="btn-close" style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}>
                <X size={20} />
              </button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', margin: '16px 0' }}>
              <div className={`status-pill ${isOnline ? 'status-online' : 'status-offline'}`} style={{ width: 'fit-content' }}>
                {isOnline ? <CheckCircle2 size={14} /> : <AlertCircle size={14} />}
                <span>{isOnline ? `Connected (${latencyMs || 0}ms)` : 'Disconnected / Unreachable'}</span>
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 700, marginBottom: '6px', color: 'var(--text-secondary)' }}>
                  Backend API URL (e.g. Render / Cloud / Localhost)
                </label>
                <input
                  type="text"
                  value={apiUrlInput}
                  onChange={(e) => setApiUrlInput(e.target.value)}
                  placeholder="https://your-backend.onrender.com or http://localhost:8000"
                  className="search-input mono"
                  style={{ width: '100%', padding: '10px 14px' }}
                />
                <span style={{ display: 'block', fontSize: '0.74rem', color: 'var(--text-muted)', marginTop: '6px' }}>
                  Leave empty to use default same-origin / proxy path.
                </span>
              </div>

              <div style={{ padding: '14px', background: 'var(--bg-subtle)', borderRadius: 'var(--radius-md)', fontSize: '0.78rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                <strong>How to connect backend:</strong>
                <ul style={{ margin: '6px 0 0 18px', padding: 0 }}>
                  <li><strong>Render Web Service:</strong> Paste your Render app URL (e.g. <code>https://universal-log-framework.onrender.com</code>).</li>
                  <li><strong>Local Dev:</strong> Run <code>npm run dev</code> and leave empty or set to <code>http://localhost:8000</code>.</li>
                  <li>Note: Render Free Tier services take 30-50s to spin up on first request.</li>
                </ul>
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: '10px' }}>
              <button onClick={handleResetToDefault} className="btn btn-secondary btn-sm">
                Reset Default
              </button>
              <button onClick={handleSaveApiUrl} className="btn btn-primary btn-sm">
                Save &amp; Test Connection
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
};
