import type {
  HealthStatus,
  MLInsights,
  NormalizedEvent,
  OverviewData,
  SecuritySummary,
} from './types';

const API_BASE = import.meta.env.VITE_API_URL || '';

export class ApiService {
  private static async request<T>(endpoint: string, options?: RequestInit): Promise<T> {
    const url = `${API_BASE}${endpoint}`;
    const response = await fetch(url, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options?.headers,
      },
    });

    if (!response.ok) {
      const errorBody = await response.text().catch(() => '');
      throw new Error(`HTTP ${response.status} (${response.statusText}): ${errorBody || 'Request failed'}`);
    }

    return response.json() as Promise<T>;
  }

  static async getHealth(): Promise<HealthStatus> {
    return this.request<HealthStatus>('/health');
  }

  static async getSummary(): Promise<SecuritySummary> {
    return this.request<SecuritySummary>('/summary');
  }

  static async getOverview(): Promise<OverviewData> {
    return this.request<OverviewData>('/api/overview');
  }

  static async getEvents(): Promise<NormalizedEvent[]> {
    return this.request<NormalizedEvent[]>('/events');
  }

  static async getMLInsights(): Promise<MLInsights> {
    return this.request<MLInsights>('/api/ml/insights');
  }

  static async getAlerts() {
    return this.request<{ title: string; severity: string; source: string; summary: string }[]>('/api/alerts');
  }

  static async getIncidents() {
    return this.request<{ title: string; severity: string; score: number }[]>('/api/incidents');
  }

  static async getAssets() {
    return this.request<{ name: string; status: string; risk: string; owner: string }[]>('/api/assets');
  }

  static async ingestLog(rawLog: string): Promise<NormalizedEvent> {
    return this.request<NormalizedEvent>('/logs', {
      method: 'POST',
      body: JSON.stringify({ log: rawLog }),
    });
  }

  static async ingestBatchLogs(logs: string[]): Promise<NormalizedEvent[]> {
    return this.request<NormalizedEvent[]>('/api/logs/batch', {
      method: 'POST',
      body: JSON.stringify({ logs }),
    });
  }

  static async clearEvents(): Promise<{ message: string; count: number }> {
    return this.request<{ message: string; count: number }>('/api/events/clear', {
      method: 'POST',
    });
  }
}
