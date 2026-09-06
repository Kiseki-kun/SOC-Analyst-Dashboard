// Types mirroring the backend's Pydantic schemas.
// Kept hand-written and narrow rather than generated: these are the shapes the
// UI actually consumes, and a mismatch shows up as a compile error.

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type AlertStatus = 'new' | 'in_review' | 'escalated' | 'resolved' | 'false_positive'
export type IncidentStatus = 'open' | 'investigating' | 'contained' | 'resolved' | 'closed'
export type Role = 'viewer' | 'analyst' | 'responder' | 'admin'

export interface Page<T> {
  items: T[]
  total: number
  page: number
  page_size: number
  pages: number
}

export interface UserRef {
  id: string
  email: string
  full_name: string
}

export interface CurrentUser extends UserRef {
  role: Role
  is_active: boolean
  last_login_at: string | null
  created_at: string
  permissions: string[]
}

export interface AppUser extends UserRef {
  role: Role
  is_active: boolean
  last_login_at: string | null
  created_at: string
}

export interface TokenResponse {
  access_token: string
  token_type: string
  expires_in: number
  user: CurrentUser
}

export interface SecurityEvent {
  id: string
  event_uid: string
  timestamp: string
  ingested_at: string
  source: string
  event_type: string
  action: string
  outcome: string
  severity: Severity
  src_ip: string | null
  dst_ip: string | null
  src_port: number | null
  dst_port: number | null
  protocol: string | null
  username: string | null
  hostname: string | null
  country_code: string | null
  city: string | null
  process_name: string | null
  file_hash: string | null
  http_method: string | null
  url_path: string | null
  http_status: number | null
  dns_query: string | null
  message: string
}

export interface SecurityEventDetail extends SecurityEvent {
  command_line: string | null
  file_path: string | null
  user_agent: string | null
  bytes_sent: number | null
  bytes_received: number | null
  latitude: number | null
  longitude: number | null
  raw: Record<string, unknown>
  analyzed: boolean
}

export interface Alert {
  id: string
  alert_uid: string
  rule_key: string
  title: string
  description: string
  severity: Severity
  confidence: number
  status: AlertStatus
  first_seen: string
  last_seen: string
  event_count: number
  src_ip: string | null
  dst_ip: string | null
  username: string | null
  hostname: string | null
  mitre_technique_id: string | null
  mitre_technique_name: string | null
  mitre_tactic: string | null
  assigned_to: UserRef | null
  incident_id: string | null
  created_at: string
  updated_at: string
  resolved_at: string | null
}

export interface Note {
  id: string
  author_email: string
  body: string
  created_at: string
}

export interface AlertDetail extends Alert {
  evidence: Record<string, unknown>
  resolution_note: string | null
  notes: Note[]
  events: SecurityEvent[]
}

export interface TimelineEntry {
  id: string
  occurred_at: string
  entry_type: string
  summary: string
  actor_email: string | null
  details: Record<string, unknown>
}

export type ResponseActionType =
  | 'simulated_ip_block'
  | 'simulated_account_disable'
  | 'simulated_host_isolation'
  | 'simulated_credential_reset'
  | 'add_ioc_to_watchlist'

export interface ResponseAction {
  id: string
  action_type: ResponseActionType
  target: string
  parameters: Record<string, unknown>
  note: string | null
  performed_by_email: string
  simulated: boolean
  created_at: string
}

export interface Incident {
  id: string
  incident_uid: string
  title: string
  description: string
  severity: Severity
  status: IncidentStatus
  assigned_to: UserRef | null
  created_by: UserRef | null
  created_at: string
  updated_at: string
  acknowledged_at: string | null
  contained_at: string | null
  resolved_at: string | null
  closed_at: string | null
  resolution_summary: string | null
}

export interface IncidentDetail extends Incident {
  alerts: Alert[]
  notes: Note[]
  response_actions: ResponseAction[]
  timeline_entries: TimelineEntry[]
}

export interface DashboardSummary {
  generated_at: string
  total_events: number
  events_last_hour: number
  events_last_24h: number
  open_alerts: number
  critical_high_open_alerts: number
  unassigned_open_alerts: number
  open_incidents: number
  auth_failures_last_24h: number
  alerts_by_severity: Record<string, number>
  alerts_by_status: Record<string, number>
  incidents_by_severity: Record<string, number>
  incidents_by_status: Record<string, number>
}

export interface TimeSeriesPoint {
  bucket: string
  count: number
}
export interface AuthTrendPoint {
  bucket: string
  success: number
  failure: number
}
export interface TopIP {
  ip: string
  event_count: number
  failure_count: number | null
}
export interface TopRule {
  rule_key: string
  alert_count: number
}
export interface MitreEntry {
  technique_id: string
  technique_name: string | null
  tactic: string | null
  alert_count: number
}
export interface TacticEntry {
  tactic: string
  alert_count: number
}
export interface EventTypeEntry {
  event_type: string
  count: number
}
export interface ResponseMetrics {
  window_days: number
  mean_time_to_acknowledge_minutes: number | null
  mean_time_to_contain_minutes: number | null
  mean_time_to_resolve_minutes: number | null
  incidents_acknowledged: number
  incidents_resolved: number
}

export interface AnalyticsOverview {
  summary: DashboardSummary
  events_over_time: TimeSeriesPoint[]
  alerts_over_time: TimeSeriesPoint[]
  authentication_trend: AuthTrendPoint[]
  top_source_ips: TopIP[]
  top_destination_ips: TopIP[]
  top_detection_rules: TopRule[]
  mitre_distribution: MitreEntry[]
  attack_categories: TacticEntry[]
  event_type_distribution: EventTypeEntry[]
  response_metrics: ResponseMetrics
}

export interface DetectionRule {
  id: string
  rule_key: string
  name: string
  description: string
  severity: Severity
  enabled: boolean
  config: Record<string, number | boolean>
  default_config: Record<string, number | boolean>
  implemented: boolean
  mitre_tactic: string | null
  mitre_technique_id: string | null
  mitre_technique_name: string | null
  updated_at: string
}

export type IOCType = 'ip_address' | 'file_hash' | 'domain' | 'url'

export interface IOC {
  id: string
  ioc_type: IOCType
  value: string
  description: string
  active: boolean
  added_by_email: string | null
  created_at: string
}

export interface AuditLogEntry {
  id: string
  timestamp: string
  actor_email: string | null
  actor_role: string | null
  action: string
  resource_type: string | null
  resource_id: string | null
  success: boolean
  ip_address: string | null
  details: Record<string, unknown>
}

export interface IPInvestigation {
  ip_address: string
  summary: {
    total_events: number
    connection_count: number
    authentication_attempts: number
    failed_authentications: number
    successful_authentications: number
    distinct_destination_ports: number
    distinct_destination_hosts: number
    first_seen: string | null
    last_seen: string | null
  }
  reputation: {
    verdict: 'benign' | 'suspicious' | 'malicious'
    score: number
    basis: string[]
    on_watchlist: boolean
    source: string
  }
  associated_usernames: string[]
  associated_hostnames: string[]
  top_destination_ports: number[]
  related_alerts: Alert[]
  related_incident_uids: string[]
  recent_events: SecurityEvent[]
}
