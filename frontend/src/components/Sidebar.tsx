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
} from 'lucide-react';
import type { HealthStatus } from '../types';

interface SidebarProps {
  currentView: string;
  setCurrentView: (view: string) => void;
  collapsed: boolean;
  setCollapsed: (collapsed: boolean) => void;
  eventCount: number;
  health: HealthStatus | null;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentView,
  setCurrentView,
  collapsed,
  setCollapsed,
  eventCount,
  health,
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
            <ShieldCheck size={22} className="text-coral" />
            <div className="brand-glow" />
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
          {collapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}
        </button>
      </div>

      {/* Navigation Groups */}
      <div className="sidebar-nav-wrap">
        <div className="nav-group">
          {!collapsed && <div className="nav-group-label">TELEMETRY & OPERATIONS</div>}
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
                  <Icon size={18} className="nav-item-icon" />
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
          {!collapsed && <div className="nav-group-label">DOCUMENTATION & APIS</div>}
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
                  <Icon size={18} className="nav-item-icon" />
                  {!collapsed && (
                    <span className="nav-item-label">{item.label}</span>
                  )}
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* Sidebar Footer / Node Telemetry Widget */}
      {!collapsed && (
        <div className="sidebar-node-widget">
          <div className="node-widget-top">
            <div className="node-info">
              <span className={`pulse-dot ${isOnline ? 'online' : 'critical'}`} />
              <span className="node-title">Node: fw-edge-01</span>
            </div>
            <span className="node-status-text">{isOnline ? 'READY' : 'OFFLINE'}</span>
          </div>

          <div className="node-metrics-list">
            <div className="node-metric-row">
              <span className="metric-lbl"><Server size={12} /> ML Model:</span>
              <span className="metric-val mono">RandomForest v1.4</span>
            </div>
            <div className="node-metric-row">
              <span className="metric-lbl"><Activity size={12} /> Ingestion:</span>
              <span className="metric-val mono">Active</span>
            </div>
          </div>
        </div>
      )}
    </aside>
  );
};
