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
import { ApiDocsView } from './components/ApiDocsView';

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
  const [summary, setSummary] = useState<SecuritySummary | null>(null);
  const [events, setEvents] = useState<NormalizedEvent[]>([]);
  const [mlInsights, setMlInsights] = useState<MLInsights | null>(null);
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [incidents, setIncidents] = useState<IncidentItem[]>([]);
  const [assets, setAssets] = useState<AssetItem[]>([]);

  const [latencyMs, setLatencyMs] = useState<number | null>(null);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [autoRefreshInterval, setAutoRefreshInterval] = useState<number>(3); // 3s default
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
        ApiService.getEvents().catch(() => []),
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
        showToast('Dashboard synchronized with backend', 'success');
      }
    } catch (err: unknown) {
      console.error('Error fetching dashboard data:', err);
      if (isManual) {
        showToast('Failed to connect to backend server', 'error');
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

  // Ingest handler
  const handleIngest = async (rawLog: string) => {
    try {
      const result = await ApiService.ingestLog(rawLog);
      showToast(`Log ingested & normalized (${result.source || 'event'})`, 'success');
      await refreshAllData(false);
      return result;
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Ingest failed', 'error');
      throw err;
    }
  };

  // Batch ingest handler
  const handleBatchIngest = async (logs: string[]) => {
    try {
      const results = await ApiService.ingestBatchLogs(logs);
      showToast(`Batch processed ${results.length} events`, 'success');
      await refreshAllData(false);
      return results;
    } catch (err: unknown) {
      const results: NormalizedEvent[] = [];
      for (const log of logs) {
        if (log.trim()) {
          const res = await ApiService.ingestLog(log);
          results.push(res);
        }
      }
      showToast(`Processed ${results.length} log events`, 'success');
      await refreshAllData(false);
      return results;
    }
  };

  // Clear events handler
  const handleClearEvents = async () => {
    try {
      await ApiService.clearEvents();
      showToast('Event store cleared', 'info');
      await refreshAllData(false);
    } catch (err) {
      console.warn('Clear endpoint failed:', err);
      showToast('Resetting buffer...', 'info');
      await refreshAllData(false);
    }
  };

  return (
    <div className="app-layout" data-theme={theme}>
      {/* Toast Notification */}
      {toast && (
        <div className={`toast-notification glass-panel toast-${toast.type} fade-in`}>
          <span>{toast.message}</span>
        </div>
      )}

      {/* App Shell with Sidebar & Main Area */}
      <div className="app-shell">
        {/* Left Sidebar */}
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

        {/* Right Main Body */}
        <div className="app-main-body">
          {/* Top Bar Header */}
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

          {/* Main Content Pages */}
          <main className="main-content">
            <div className="container">
              {/* LANDING PAGE VIEW */}
              {currentView === 'landing' && (
                <LandingPage
                  setCurrentView={setCurrentView}
                  onIngest={handleIngest}
                  eventCount={events.length}
                />
              )}

              {/* DASHBOARD & SPECIFIC VIEWS (Show Top KPI metrics) */}
              {currentView !== 'landing' && (
                <>
                  <MetricsCards
                    summary={summary}
                    mlInsights={mlInsights}
                    eventCount={events.length}
                  />

                  {/* 1. SOC ANALYTICS DASHBOARD */}
                  {currentView === 'analytics' && (
                    <div className="tab-pane fade-in">
                      <div className="dashboard-grid">
                        <ThreatRiskGauge mlInsights={mlInsights} />
                        <SeverityDonutChart events={events} />
                        <div className="dashboard-full-width">
                          <EventTimelineChart events={events} />
                        </div>
                        <SourcesBarChart events={events} />
                        <GeoThreatMap events={events} />
                      </div>
                    </div>
                  )}

                  {/* 2. PIPELINE STUDIO (INGEST) */}
                  {currentView === 'ingest' && (
                    <div className="tab-pane fade-in">
                      <LogIngestionStudio
                        onIngest={handleIngest}
                        onBatchIngest={handleBatchIngest}
                      />
                    </div>
                  )}

                  {/* 3. SIEM EVENT EXPLORER */}
                  {currentView === 'events' && (
                    <div className="tab-pane fade-in">
                      <EventExplorerTable events={events} />
                    </div>
                  )}

                  {/* 4. SECURITY PULSE */}
                  {currentView === 'pulse' && (
                    <div className="tab-pane fade-in">
                      <SecurityPulse
                        alerts={alerts}
                        incidents={incidents}
                        assets={assets}
                      />
                    </div>
                  )}

                  {/* 5. ML DECISION ENGINE */}
                  {currentView === 'ml' && (
                    <div className="tab-pane fade-in">
                      <MLFeatureInfluence
                        mlInsights={mlInsights}
                        events={events}
                      />
                    </div>
                  )}

                  {/* 6. API REFERENCE */}
                  {currentView === 'api-docs' && (
                    <div className="tab-pane fade-in">
                      <ApiDocsView />
                    </div>
                  )}
                </>
              )}
            </div>
          </main>

          {/* Footer Component */}
          <Footer
            setCurrentView={setCurrentView}
            health={health}
            eventCount={events.length}
          />
        </div>
      </div>
    </div>
  );
}

export default App;
