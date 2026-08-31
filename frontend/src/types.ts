export interface EventMetadata {
  processing_status?: string;
  source_format?: string;
  parser?: string;
  received_at?: string;
  [key: string]: unknown;
}

export interface EventDetails {
  action?: string;
  type?: string;
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'info' | string;
  message?: string;
  code?: string | number;
  reason?: string;
  [key: string]: unknown;
}

export interface NetworkDetails {
  source_ip?: string;
  destination_ip?: string;
  src_ip?: string;
  dst_ip?: string;
  source_port?: number | string;
  destination_port?: number | string;
  src_port?: number | string;
  dst_port?: number | string;
  protocol?: string;
  bytes?: number;
  packets?: number;
  [key: string]: unknown;
}

export interface EnrichmentDetails {
  country?: string;
  country_name?: string;
  city?: string;
  asn?: string;
  organization?: string;
  geo_risk_score?: number;
  [key: string]: unknown;
}

export interface ThreatDetails {
  reputation?: 'benign' | 'suspicious' | 'malicious' | 'unknown' | string;
  threat_type?: string;
  confidence?: number;
  c2_indicators?: boolean;
  notes?: string;
  [key: string]: unknown;
}

export interface AuditMetadata {
  sha256_hash: string;
  short_hash: string;
  timestamp: string;
  bytes_size: number;
  source: string;
  tamper_proof_status: string;
  backup_path?: string;
  backup_id?: string;
}

export interface QuarantineMetadata {
  quarantine_id: string;
  sha256_hash: string;
  quarantined_at: string;
  reason: string;
  risk_score: number;
  source: string;
  raw_payload?: string;
  status: 'ISOLATED' | 'RELEASED' | 'PURGED' | string;
  file_path?: string;
}

export interface NormalizedEvent {
  id?: string;
  timestamp?: string;
  source?: string;
  event_type?: string;
  host?: string;
  event?: EventDetails;
  network?: NetworkDetails;
  enrichment?: EnrichmentDetails;
  threat?: ThreatDetails;
  metadata?: EventMetadata;
  audit?: AuditMetadata;
  quarantine?: QuarantineMetadata;
  raw_log?: string;
  anomaly_score?: number;
  threat_label?: string;
  [key: string]: unknown;
}

export interface MLInsightDetail {
  source: string;
  score: number;
  label: 'benign' | 'monitor' | 'suspicious' | 'critical' | string;
  severity: string;
}

export interface MLInsights {
  anomaly_score: number;
  threat_label: 'benign' | 'monitor' | 'suspicious' | 'critical' | string;
  total_evaluated: number;
  model: string;
  details: MLInsightDetail[];
}

export interface SecuritySummary {
  total_events: number;
  high_severity: number;
  blocked_events: number;
  suspicious_ips: string[];
  sources: string[];
  ml_anomaly_score: number;
  ml_threat_label: string;
  last_updated: string;
}

export interface AlertItem {
  id?: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | string;
  source: string;
  summary: string;
  timestamp?: string;
}

export interface IncidentItem {
  id?: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | string;
  score: number;
  source?: string;
  status?: string;
}

export interface AssetItem {
  name: string;
  status: 'healthy' | 'watch' | 'critical' | 'offline' | string;
  risk: 'low' | 'medium' | 'high' | string;
  owner: string;
  ip?: string;
}

export interface OverviewData {
  summary: SecuritySummary;
  alerts: AlertItem[];
  incidents: IncidentItem[];
  assets: AssetItem[];
  events: NormalizedEvent[];
  generated_at: string;
}

export interface HealthStatus {
  status: string;
  service: string;
  timestamp: string;
  uptime_seconds: number;
  total_events: number;
  sources: string[];
}

export interface IngestResponse extends NormalizedEvent {
  error?: string;
}

export type ThemeMode = 'light' | 'dark' | 'cyber';

