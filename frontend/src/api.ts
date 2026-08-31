import type {
  HealthStatus,
  MLInsights,
  NormalizedEvent,
  OverviewData,
  SecuritySummary,
} from './types';

export function getApiBase(): string {
  if (typeof window !== 'undefined') {
    const custom = localStorage.getItem('ulf_api_base');
    if (custom && custom.trim()) return custom.trim().replace(/\/+$/, '');
  }
  const envUrl = import.meta.env.VITE_API_URL || '';
  return envUrl ? envUrl.trim().replace(/\/+$/, '') : '';
}

export function setApiBase(url: string): void {
  if (typeof window !== 'undefined') {
    if (url.trim()) {
      localStorage.setItem('ulf_api_base', url.trim().replace(/\/+$/, ''));
    } else {
      localStorage.removeItem('ulf_api_base');
    }
  }
}

export class ApiService {
  private static async request<T>(endpoint: string, options?: RequestInit): Promise<T> {
    const base = getApiBase();
    const cleanEndpoint = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
    const url = `${base}${cleanEndpoint}`;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 60000);

    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal,
        headers: {
          'Content-Type': 'application/json',
          ...options?.headers,
        },
      });

      if (!response.ok) {
        const errorBody = await response.text().catch(() => '');
        throw new Error(`HTTP ${response.status} (${response.statusText}): ${errorBody || 'Request failed'}`);
      }

      return (await response.json()) as T;
    } finally {
      clearTimeout(timeoutId);
    }
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
    const response = await this.request<NormalizedEvent[] | { results: NormalizedEvent[] }>('/api/logs/batch', {
      method: 'POST',
      body: JSON.stringify({ logs }),
    });
    if (Array.isArray(response)) return response;
    if (response && Array.isArray(response.results)) return response.results;
    return [];
  }

  static async clearEvents(): Promise<{ message: string; count: number }> {
    return this.request<{ message: string; count: number }>('/api/events/clear', {
      method: 'POST',
    });
  }
}
