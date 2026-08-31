import { useState, useEffect, useCallback, useRef } from 'react';
import './App.css';
import { ApiService } from './api';
import type {
  HealthStatus,
  SecuritySummary,
  NormalizedEvent,
  MLInsights,
  AlertItem,
  IncidentItem,
  AssetItem,
  ThemeMode,
} from './types';
import { Header } from './components/Header';
import { Sidebar } from './components/Sidebar';
import { Footer } from './components/Footer';
import { LandingPage } from './components/LandingPage';
import { MetricsCards } from './components/MetricsCards';
import { ThreatRiskGauge } from './components/ThreatRiskGauge';
import { EventTimelineChart } from './components/EventTimelineChart';
import { SeverityDonutChart } from './components/SeverityDonutChart';
import { SourcesBarChart } from './components/SourcesBarChart';
import { GeoThreatMap } from './components/GeoThreatMap';
import { LogIngestionStudio } from './components/LogIngestionStudio';
import { EventExplorerTable } from './components/EventExplorerTable';
import { SecurityPulse } from './components/SecurityPulse';
import { MLFeatureInfluence } from './components/MLFeatureInfluence';
import { MitreAttackMatrix } from './components/MitreAttackMatrix';
import { ApiDocsView } from './components/ApiDocsView';

const INITIAL_EVENTS: NormalizedEvent[] = [
  {
    timestamp: '2026-08-31T10:32:00Z',
    source: 'firewall',
    event: { action: 'blocked', type: 'firewall_event', severity: 'high', message: 'Perimeter drop rule enforced' },
    network: { source_ip: '192.168.1.10', destination_ip: '8.8.8.8', source_port: '443', destination_port: '53' },
    enrichment: { country: 'IN', city: 'Mumbai', geo_risk: 0.15 },
    threat: { reputation: 'unknown' },
  },
  {
    timestamp: '2026-08-31T10:31:00Z',
    source: 'linux',
    event: { action: 'fail', type: 'authentication', severity: 'medium', message: 'Failed password for invalid user admin' },
    network: { source_ip: '10.0.0.5', destination_ip: '10.0.0.8', source_port: '22', destination_port: '22' },
    enrichment: { country: 'US', city: 'Ashburn', geo_risk: 0.25 },
    threat: { reputation: 'benign' },
  },
  {
    timestamp: '2026-08-31T10:30:00Z',
    source: 'api',
    event: { action: 'deny', type: 'threat', severity: 'critical', message: 'C2 beaconing signature matched' },
    network: { source_ip: '1.2.3.4', destination_ip: '10.5.2.4', source_port: '443', destination_port: '58920' },
    enrichment: { country: 'CN', city: 'Hangzhou', geo_risk: 0.95 },
    threat: { reputation: 'suspicious', category: 'botnet' },
  },
];

const INITIAL_SUMMARY: SecuritySummary = {
  total_events: 14,
  high_severity: 4,
  blocked_events: 6,
  suspicious_ips: ['1.2.3.4', '185.220.101.5'],
  sources: ['api', 'firewall', 'linux', 'syslog'],
  ml_anomaly_score: 0.72,
  ml_threat_label: 'suspicious',
  last_updated: new Date().toISOString(),
};

const INITIAL_ML_INSIGHTS: MLInsights = {
  model: 'RandomForestClassifier (100 Estimators)',
  anomaly_score: 0.72,
  threat_label: 'suspicious',
  total_evaluated: 14,
  details: [
    { source: 'api', score: 0.94, label: 'suspicious', severity: 'critical' },
    { source: 'firewall', score: 0.78, label: 'suspicious', severity: 'high' },
    { source: 'linux', score: 0.45, label: 'medium_risk', severity: 'medium' },
  ],
};

const INITIAL_ALERTS: AlertItem[] = [
  {
    title: 'C2 beaconing detected',
    severity: 'high',
    source: '1.2.3.4',
    summary: 'External host established repeated outbound connections to a suspicious remote endpoint.',
  },
  {
    title: 'Failed admin logins',
    severity: 'medium',
    source: '10.0.0.5',
    summary: 'Privileged SSH failures exceeded threshold across multiple identity checks.',
  },
  {
    title: 'Geo-risk flagged',
    severity: 'low',
    source: 'CN',
    summary: 'Traffic from a high-risk region matched historical threat intelligence data.',
  },
];

const INITIAL_INCIDENTS: IncidentItem[] = [
  { title: 'Malicious outbound connection', severity: 'high', score: 92 },
  { title: 'Repeated authentication failures', severity: 'medium', score: 68 },
  { title: 'Geo-anomaly on internal portal', severity: 'low', score: 47 },
];

const INITIAL_ASSETS: AssetItem[] = [
  { name: 'web-01', status: 'healthy', risk: 'low', owner: 'Platform' },
  { name: 'api-gateway', status: 'watch', risk: 'medium', owner: 'Security' },
  { name: 'db-prod-02', status: 'critical', risk: 'high', owner: 'Data' },
];

export function App() {
  const [currentView, setCurrentView] = useState<string>('landing');
  const [sidebarCollapsed, setSidebarCollapsed] = useState<boolean>(false);

  // Theme State ('light' | 'dark' | 'cyber')
  const [theme, setTheme] = useState<ThemeMode>(() => {
    const saved = localStorage.getItem('ulf_theme');
    if (saved === 'dark' || saved === 'cyber' || saved === 'light') {
      return saved;
    }
    return 'light';
  });

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('ulf_theme', theme);
  }, [theme]);

  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [summary, setSummary] = useState<SecuritySummary>(INITIAL_SUMMARY);
  const [events, setEvents] = useState<NormalizedEvent[]>(INITIAL_EVENTS);
  const [mlInsights, setMlInsights] = useState<MLInsights | null>(INITIAL_ML_INSIGHTS);
  const [alerts, setAlerts] = useState<AlertItem[]>(INITIAL_ALERTS);
  const [incidents, setIncidents] = useState<IncidentItem[]>(INITIAL_INCIDENTS);
  const [assets, setAssets] = useState<AssetItem[]>(INITIAL_ASSETS);

  const [latencyMs, setLatencyMs] = useState<number | null>(null);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [autoRefreshInterval, setAutoRefreshInterval] = useState<number>(3);
  const [toast, setToast] = useState<{ message: string; type: 'success' | 'info' | 'error' } | null>(null);

  const isFirstLoad = useRef(true);

  const showToast = (message: string, type: 'success' | 'info' | 'error' = 'info') => {
    setToast({ message, type });
    setTimeout(() => {
      setToast(null);
    }, 3500);
  };

  // Main data sync function
  const refreshAllData = useCallback(async (isManual = false) => {
    if (isManual) setIsRefreshing(true);
    const startTime = performance.now();

    try {
      const [healthData, summaryData, eventsData, overviewData, mlData] = await Promise.all([
        ApiService.getHealth().catch(() => null),
        ApiService.getSummary().catch(() => null),
        ApiService.getEvents().catch(() => null),
        ApiService.getOverview().catch(() => null),
        ApiService.getMLInsights().catch(() => null),
      ]);

      const endTime = performance.now();
      setLatencyMs(Math.round(endTime - startTime));

      if (healthData) setHealth(healthData);
      if (summaryData) setSummary(summaryData);
      if (eventsData && eventsData.length > 0) setEvents(eventsData);
      if (mlData) setMlInsights(mlData);

      if (overviewData) {
        if (overviewData.alerts) setAlerts(overviewData.alerts);
        if (overviewData.incidents) setIncidents(overviewData.incidents);
        if (overviewData.assets) setAssets(overviewData.assets);
      }

      if (isManual) {
        if (healthData) {
          showToast('Dashboard synchronized with live backend', 'success');
        } else {
          showToast('Backend offline - using local cache / simulated stream', 'info');
        }
      }
    } catch (err: unknown) {
      console.error('Error fetching dashboard data:', err);
      if (isManual) {
        showToast('Backend disconnected', 'error');
      }
    } finally {
      if (isManual) setIsRefreshing(false);
    }
  }, []);

  // Initial load
  useEffect(() => {
    if (isFirstLoad.current) {
      isFirstLoad.current = false;
      refreshAllData();
    }
  }, [refreshAllData]);

  // Periodic polling
  useEffect(() => {
    if (autoRefreshInterval <= 0) return;

    const timer = setInterval(() => {
      refreshAllData(false);
    }, autoRefreshInterval * 1000);

    return () => clearInterval(timer);
  }, [autoRefreshInterval, refreshAllData]);

  // Client-side fallback normalizer when backend is offline
  const clientFallbackNormalize = (rawLog: string): NormalizedEvent => {
    const trimmed = rawLog.trim();
    const srcMatch = trimmed.match(/src=([^\s]+)/i) || trimmed.match(/from\s+([0-9.]+)/i);
    const dstMatch = trimmed.match(/dst=([^\s]+)/i);
    const actionMatch = trimmed.match(/action=([^\s]+)/i) || trimmed.match(/(deny|block|drop|allow|permit|login|failed)/i);
    const countryMatch = trimmed.match(/country=([^\s]+)/i);
    const msgMatch = trimmed.match(/msg="([^"]+)"/i) || trimmed.match(/msg=([^\s]+)/i);

    const srcIp = srcMatch ? srcMatch[1] : '1.2.3.4';
    const dstIp = dstMatch ? dstMatch[1] : '10.5.2.4';
    const act = actionMatch ? actionMatch[1].toLowerCase() : 'deny';
    const country = countryMatch ? countryMatch[1].toUpperCase() : srcIp.startsWith('1.') ? 'CN' : 'US';
    const isSuspicious = srcIp === '1.2.3.4' || country === 'CN' || country === 'RU' || act === 'deny' || act === 'block';

    return {
      timestamp: new Date().toISOString(),
      source: trimmed.startsWith('CEF:') ? 'cef' : trimmed.startsWith('LEEF:') ? 'leef' : trimmed.startsWith('{') ? 'json' : 'firewall',
      event: {
        action: act,
        type: isSuspicious ? 'threat' : 'security_event',
        severity: isSuspicious ? 'critical' : 'low',
        message: msgMatch ? msgMatch[1] : 'Normalized security telemetry event',
      },
      network: {
        source_ip: srcIp,
        destination_ip: dstIp,
        source_port: '443',
        destination_port: '58920',
      },
      enrichment: {
        country: country,
        geo_risk: isSuspicious ? 0.95 : 0.1,
      },
      threat: {
        reputation: isSuspicious ? 'suspicious' : 'benign',
        category: isSuspicious ? 'botnet' : 'general',
      },
    };
  };

  // Ingest handler
  const handleIngest = async (rawLog: string): Promise<NormalizedEvent> => {
    try {
      const result = await ApiService.ingestLog(rawLog);
      showToast(`Log ingested & normalized (${result.source || 'event'})`, 'success');
      await refreshAllData(false);
      return result;
    } catch (err: unknown) {
      console.warn('Backend unavailable, utilizing local normalization engine fallback:', err);
      const fallbackResult = clientFallbackNormalize(rawLog);
      setEvents((prev) => [fallbackResult, ...prev]);
      setSummary((prev) => ({
        ...prev,
        total_events: prev.total_events + 1,
        blocked_events: fallbackResult.event?.action === 'deny' ? prev.blocked_events + 1 : prev.blocked_events,
        high_severity: fallbackResult.event?.severity === 'critical' ? prev.high_severity + 1 : prev.high_severity,
      }));
      showToast('Log normalized via in-browser engine (Backend Offline)', 'info');
      return fallbackResult;
    }
  };

  // Batch Ingest handler
  const handleBatchIngest = async (logs: string[]): Promise<NormalizedEvent[]> => {
    try {
      const results = await ApiService.ingestBatchLogs(logs);
      showToast(`Batch of ${results.length} logs successfully processed`, 'success');
      if (results.length > 0) {
        setEvents(results);
      }
      await refreshAllData(false);
      return results;
    } catch (err: unknown) {
      console.warn('Backend unavailable, batch fallback:', err);
      const fallbackResults = logs.map(clientFallbackNormalize);
      setEvents((prev) => [...fallbackResults, ...prev]);
      setSummary((prev) => ({
        ...prev,
        total_events: prev.total_events + fallbackResults.length,
      }));
      showToast(`Batch of ${fallbackResults.length} logs normalized via in-browser engine`, 'info');
      return fallbackResults;
    }
  };

  // Clear events handler
  const handleClearEvents = async () => {
    try {
      await ApiService.clearEvents();
      setEvents([]);
      showToast('Event store cleared', 'info');
      await refreshAllData(false);
    } catch (err: unknown) {
      setEvents([]);
      showToast('Local event buffer reset', 'info');
    }
  };

  return (
    <div className="app-layout">
      {/* Toast Notification */}
      {toast && (
        <div className={`toast-notification toast-${toast.type} fade-in`}>
          {toast.message}
        </div>
      )}

      <div className="app-shell">
        {/* Collapsible Left Sidebar */}
        <Sidebar
          currentView={currentView}
          setCurrentView={setCurrentView}
          collapsed={sidebarCollapsed}
          setCollapsed={setSidebarCollapsed}
          eventCount={events.length}
          health={health}
          theme={theme}
          setTheme={setTheme}
        />

        {/* Main Body */}
        <div className="app-main-body">
          {/* Top Sticky Header */}
          <Header
            currentView={currentView}
            setCurrentView={setCurrentView}
            health={health}
            latencyMs={latencyMs}
            isRefreshing={isRefreshing}
            onRefresh={() => refreshAllData(true)}
            autoRefreshInterval={autoRefreshInterval}
            setAutoRefreshInterval={setAutoRefreshInterval}
            onClearEvents={handleClearEvents}
            eventCount={events.length}
            theme={theme}
            setTheme={setTheme}
          />

          <div className="main-content">
            <div className="container">
              {/* LANDING PAGE VIEW */}
              {currentView === 'landing' && (
                <LandingPage
                  setCurrentView={setCurrentView}
                  onIngest={handleIngest}
                  eventCount={events.length}
                />
              )}

              {/* DASHBOARD / ANALYTICS VIEW */}
              {currentView === 'analytics' && (
                <div className="fade-in">
                  <MetricsCards
                    summary={summary}
                    mlInsights={mlInsights}
                    eventCount={events.length}
                  />

                  <div className="dashboard-grid">
                    <ThreatRiskGauge
                      mlInsights={mlInsights}
                    />
                    <EventTimelineChart events={events} />
                  </div>

                  <div className="dashboard-grid">
                    <SeverityDonutChart events={events} />
                    <SourcesBarChart events={events} />
                  </div>

                  <div className="dashboard-grid">
                    <div className="dashboard-full-width">
                      <MitreAttackMatrix events={events} />
                    </div>
                  </div>

                  <div className="dashboard-grid">
                    <div className="dashboard-full-width">
                      <GeoThreatMap events={events} />
                    </div>
                  </div>
                </div>
              )}

              {/* INGESTION & PIPELINE STUDIO */}
              {currentView === 'ingest' && (
                <div className="fade-in">
                  <LogIngestionStudio
                    onIngest={handleIngest}
                    onBatchIngest={handleBatchIngest}
                  />
                </div>
              )}

              {/* EVENT EXPLORER / SIEM TABLE */}
              {currentView === 'events' && (
                <div className="fade-in">
                  <EventExplorerTable events={events} />
                </div>
              )}

              {/* SECURITY PULSE VIEW */}
              {currentView === 'pulse' && (
                <div className="fade-in">
                  <SecurityPulse
                    alerts={alerts}
                    incidents={incidents}
                    assets={assets}
                  />
                </div>
              )}

              {/* ML ENGINE & FEATURE WEIGHTS */}
              {currentView === 'ml' && (
                <div className="fade-in">
                  <MLFeatureInfluence
                    mlInsights={mlInsights}
                    events={events}
                  />
                </div>
              )}

              {/* API DOCUMENTATION */}
              {currentView === 'api-docs' && (
                <div className="fade-in">
                  <ApiDocsView />
                </div>
              )}
            </div>
          </div>

          {/* Footer Component - ONLY on Landing/Home Overview Page */}
          {currentView === 'landing' && (
            <Footer
              setCurrentView={setCurrentView}
              eventCount={events.length}
              health={health}
            />
          )}
        </div>
      </div>
    </div>
  );
}

export default App;
