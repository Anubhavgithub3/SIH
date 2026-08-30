import React from 'react';
import {
  Home,
  LayoutDashboard,
  FileCode2,
  Database,
  Radio,
  Cpu,
  BookOpen,
  ChevronLeft,
  ChevronRight,
  ShieldCheck,
  Server,
  Activity,
  Sun,
  Moon,
  Sparkles,
} from 'lucide-react';
import type { HealthStatus, ThemeMode } from '../types';

interface SidebarProps {
  currentView: string;
  setCurrentView: (view: string) => void;
  collapsed: boolean;
  setCollapsed: (collapsed: boolean) => void;
  eventCount: number;
  health: HealthStatus | null;
  theme: ThemeMode;
  setTheme: (theme: ThemeMode) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentView,
  setCurrentView,
  collapsed,
  setCollapsed,
  eventCount,
  health,
  theme,
  setTheme,
}) => {
  const isOnline = !!health;

  const mainNavItems = [
    { id: 'landing', label: 'Home / Overview', icon: Home },
    { id: 'analytics', label: 'SOC Dashboard', icon: LayoutDashboard },
    { id: 'ingest', label: 'Pipeline Studio', icon: FileCode2 },
    { id: 'events', label: 'SIEM Explorer', icon: Database, badge: eventCount },
    { id: 'pulse', label: 'Security Pulse', icon: Radio },
    { id: 'ml', label: 'ML Decision Engine', icon: Cpu },
  ];

  const secondaryNavItems = [
    { id: 'api-docs', label: 'API Reference', icon: BookOpen },
  ];

  return (
    <aside className={`sidebar-container ${collapsed ? 'collapsed' : ''}`}>
      {/* Sidebar Header with Brand */}
      <div className="sidebar-header">
        <div className="sidebar-brand" onClick={() => setCurrentView('landing')}>
          <div className="sidebar-brand-icon">
            <ShieldCheck size={20} className="text-coral" />
          </div>
          {!collapsed && (
            <div className="sidebar-brand-text">
              <span className="brand-name">ULF CORE</span>
              <span className="brand-tagline">SOC Pipeline</span>
            </div>
          )}
        </div>

        <button
          onClick={() => setCollapsed(!collapsed)}
          className="sidebar-toggle-btn"
          title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {collapsed ? <ChevronRight size={15} /> : <ChevronLeft size={15} />}
        </button>
      </div>

      {/* Navigation Groups */}
      <div className="sidebar-nav-wrap">
        <div className="nav-group">
          {!collapsed && <div className="nav-group-label">OPERATIONS</div>}
          <div className="nav-items-list">
            {mainNavItems.map((item) => {
              const Icon = item.icon;
              const isActive = currentView === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setCurrentView(item.id)}
                  className={`nav-item-btn ${isActive ? 'active' : ''}`}
                  title={collapsed ? item.label : undefined}
                >
                  <Icon size={17} className="nav-item-icon" />
                  {!collapsed && (
                    <span className="nav-item-label">{item.label}</span>
                  )}
                  {!collapsed && typeof item.badge === 'number' && (
                    <span className="nav-item-badge mono">{item.badge}</span>
                  )}
                </button>
              );
            })}
          </div>
        </div>

        <div className="nav-group">
          {!collapsed && <div className="nav-group-label">SPECS & APIS</div>}
          <div className="nav-items-list">
            {secondaryNavItems.map((item) => {
              const Icon = item.icon;
              const isActive = currentView === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setCurrentView(item.id)}
                  className={`nav-item-btn ${isActive ? 'active' : ''}`}
                  title={collapsed ? item.label : undefined}
                >
                  <Icon size={17} className="nav-item-icon" />
                  {!collapsed && (
                    <span className="nav-item-label">{item.label}</span>
                  )}
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* Sidebar Footer with Theme Switcher & Node Status */}
      <div className="sidebar-bottom-section">
        {!collapsed && (
          <div className="sidebar-theme-row">
            <span className="nav-group-label">APPEARANCE</span>
            <div className="theme-switch-group">
              <button
                onClick={() => setTheme('light')}
                className={`theme-switch-btn ${theme === 'light' ? 'active' : ''}`}
                title="Light / White Mode"
              >
                <Sun size={12} />
                <span>Light</span>
              </button>
              <button
                onClick={() => setTheme('dark')}
                className={`theme-switch-btn ${theme === 'dark' ? 'active' : ''}`}
                title="Dark Mode"
              >
                <Moon size={12} />
                <span>Dark</span>
              </button>
              <button
                onClick={() => setTheme('cyber')}
                className={`theme-switch-btn ${theme === 'cyber' ? 'active' : ''}`}
                title="Color Mode"
              >
                <Sparkles size={12} />
                <span>Color</span>
              </button>
            </div>
          </div>
        )}

        {!collapsed && (
          <div className="sidebar-node-widget">
            <div className="node-widget-top">
              <div className="node-info">
                <span className={`pulse-dot ${isOnline ? 'online' : 'critical'}`} />
                <span className="node-title">Node: fw-edge-01</span>
              </div>
              <span className="node-status-text">{isOnline ? 'ONLINE' : 'OFFLINE'}</span>
            </div>

            <div className="node-metrics-list">
              <div className="node-metric-row">
                <span className="metric-lbl"><Server size={11} /> ML Model:</span>
                <span className="metric-val mono">RandomForest v1.4</span>
              </div>
              <div className="node-metric-row">
                <span className="metric-lbl"><Activity size={11} /> Ingestion:</span>
                <span className="metric-val mono">Active</span>
              </div>
            </div>
          </div>
        )}
      </div>
    </aside>
  );
};
