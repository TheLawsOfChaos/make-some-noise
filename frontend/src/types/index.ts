export interface EventType {
  id: string;
  name: string;
  category: string;
  description: string;
  event_ids?: string[];
}

export interface EventTemplate {
  id: string;
  name: string;
  category: string;
  event_id?: string;
  format: string;
  description?: string;
  source?: 'builtin' | 'custom';
}

export interface GeneratedEvent {
  id: string;
  type: string;
  event_id?: string;
  timestamp: string;
  raw_event: string;
  fields: Record<string, unknown>;
  sourcetype: string;
}

export interface GenerateRequest {
  event_type: string;
  event_id?: string;
  count: number;
  destination_id?: string;
  overrides?: Record<string, unknown>;
  rate_per_second?: number;
}

export interface GenerateResponse {
  success: boolean;
  events_created: number;
  events_sent: number;
  destination?: string;
  errors?: string[];
  preview?: GeneratedEvent[];
}

export type DestinationType = 'syslog_udp' | 'syslog_tcp' | 'hec' | 'file';

export interface DestinationConfig {
  // Syslog
  host?: string;
  port?: number;
  facility?: number;
  severity?: number;
  format?: string;
  // HEC
  url?: string;
  token?: string;
  index?: string;
  source?: string;
  sourcetype?: string;
  verify_ssl?: boolean;
  batch_size?: number;
  // File
  file_path?: string;
  max_size_mb?: number;
  rotate_keep?: number;
}

export interface Destination {
  id: string;
  name: string;
  type: DestinationType;
  description?: string;
  config: DestinationConfig;
  created_at: string;
  updated_at: string;
  last_used?: string;
  events_sent: number;
}

export interface TestConnectionResponse {
  success: boolean;
  message: string;
  latency_ms?: number;
  error?: string;
}

export interface HealthResponse {
  status: string;
  version: string;
  uptime: string;
  timestamp: string;
}

// Noise Generation Types
export interface EnabledEventSource {
  event_type_id: string;
  template_ids?: string[];
  weight: number;
  enabled: boolean;
  destination_id?: string; // Per-source destination (overrides global)
}

export interface NoiseConfig {
  id?: string;
  name?: string;
  destination_id?: string; // Global fallback destination
  rate_per_second: number;
  enabled_sources: EnabledEventSource[];
  created_at?: string;
  updated_at?: string;
}

export interface NoiseStats {
  total_generated: number;
  total_sent: number;
  total_errors: number;
  events_per_second: number;
  last_event_at?: string;
  by_event_type: Record<string, number>;
  by_template: Record<string, number>;
  duration_seconds: number;
  error_samples?: string[];
}

export interface NoiseStatus {
  running: boolean;
  started_at?: string;
  current_config?: NoiseConfig;
  stats: NoiseStats;
}

export interface NoiseStartRequest {
  destination_id?: string; // Global fallback destination
  rate_per_second: number;
  enabled_sources: EnabledEventSource[];
}

export interface NoiseUpdateRequest {
  rate_per_second?: number;
  enabled_sources?: EnabledEventSource[];
}

export interface EventSourceInfo {
  event_type: EventType;
  templates: EventTemplate[];
}

export interface EventSourceTree {
  categories: Record<string, EventSourceInfo[]>;
}
