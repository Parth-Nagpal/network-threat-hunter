export type AlertStatus = 'open' | 'investigating' | 'resolved' | 'false_positive'
export type Severity = 'low' | 'medium' | 'high' | 'critical' | string

export interface Alert {
  id: number
  timestamp: string
  rule_name: string
  alert_type: string
  src_ip: string
  dst_ip: string
  description: string
  evidence: string
  status: AlertStatus
  severity: Severity
  created_at: string
}

export interface TimelineItem {
  timestamp: string
  type: string
  rule_name: string
  severity: Severity
  source_ip: string
  destination_ip: string
  evidence: string
}

export interface IncidentAlert {
  id: number
  timestamp: string
  type: string
  rule_name: string
  severity: Severity
  source_ip: string
  destination_ip: string
  description: string
  evidence: string
}

export interface Technique {
  technique_id: string
  name: string
  description: string
  tactic: string
  source_detection_type: string
}

export interface InvestigationNote {
  id: number
  incident_id: number
  content: string
  created_at: string
}

export interface InvestigationAction {
  id: number
  incident_id: number
  action_type: 'reviewed' | 'marked_suspicious' | 'marked_benign' | 'escalated'
  comment: string
  created_at: string
}

export interface TelemetryEvent {
  id: number
  event_type: string
  timestamp: string
  source_ip: string
  destination_ip: string
  source_port: number | null
  destination_port: number | null
  protocol: string
  details: Record<string, unknown>
}

export interface IOCSet {
  ip_addresses: string[]
  domains: string[]
  urls: string[]
  destination_ports: number[]
}

export interface Incident {
  id: number
  title: string
  summary: string
  severity: Severity
  status: AlertStatus
  created_at: string
  updated_at: string
  alerts?: IncidentAlert[]
  timeline?: TimelineItem[]
  related_telemetry?: TelemetryEvent[]
  iocs?: IOCSet
  notes?: InvestigationNote[]
  actions?: InvestigationAction[]
  mitre_techniques?: Technique[]
}

export interface HuntFilters {
  source_ip?: string
  destination_ip?: string
  source_port?: string | number
  destination_port?: string | number
  protocol?: string
  timestamp_from?: string
  timestamp_to?: string
  limit?: string | number
}

const API_BASE = (import.meta.env.VITE_API_URL || 'http://localhost:8000').replace(/\/$/, '')

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers: { ...(init?.body ? { 'Content-Type': 'application/json' } : {}), ...init?.headers },
    })
  } catch {
    throw new Error(`Could not reach the API at ${API_BASE}. Check that the backend is running.`)
  }
  if (!response.ok) {
    let message = `Request failed (${response.status})`
    try {
      const body = await response.json() as { detail?: string }
      if (body.detail) message = body.detail
    } catch { /* Keep the HTTP status message when there is no JSON error body. */ }
    throw new Error(message)
  }
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

function queryString(values: object): string {
  const params = new URLSearchParams()
  Object.entries(values).forEach(([key, value]) => {
    if (value !== undefined && String(value).trim() !== '') params.set(key, String(value))
  })
  const query = params.toString()
  return query ? `?${query}` : ''
}

export const api = {
  health: () => request<{ status: string; database: string }>('/health'),
  alerts: (filters: Record<string, string | number | undefined> = {}) =>
    request<Alert[]>(`/api/alerts${queryString(filters)}`),
  allAlerts: async (): Promise<Alert[]> => {
    const records: Alert[] = []
    let skip = 0
    while (true) {
      const page = await api.alerts({ skip, limit: 500 })
      records.push(...page)
      if (page.length < 500) return records
      skip += page.length
    }
  },
  alert: (id: number) => request<Alert>(`/api/alerts/${id}`),
  updateAlertStatus: (id: number, status: AlertStatus) =>
    request<Alert>(`/api/alerts/${id}/status`, { method: 'PATCH', body: JSON.stringify({ status }) }),
  hunt: (filters: HuntFilters) =>
    request<TelemetryEvent[]>(`/api/hunt${queryString(filters)}`),
  incidents: (limit = 500) => request<Incident[]>(`/api/incidents?limit=${limit}`),
  investigation: (id: number, window_minutes = 10) =>
    request<Incident>(`/api/incidents/${id}/investigation${queryString({ window_minutes })}`),
  updateIncident: (id: number, update: Partial<Pick<Incident, 'status' | 'severity'>>) =>
    request<Incident>(`/api/incidents/${id}`, { method: 'PATCH', body: JSON.stringify(update) }),
  addNote: (id: number, content: string) =>
    request<InvestigationNote>(`/api/incidents/${id}/notes`, { method: 'POST', body: JSON.stringify({ content }) }),
  deleteNote: (incidentId: number, noteId: number) =>
    request<{ status: string }>(`/api/incidents/${incidentId}/notes/${noteId}`, { method: 'DELETE' }),
  addAction: (id: number, action_type: InvestigationAction['action_type'], comment: string) =>
    request<InvestigationAction>(`/api/incidents/${id}/actions`, {
      method: 'POST', body: JSON.stringify({ action_type, comment }),
    }),
  addAlertToIncident: (incidentId: number, alertId: number) =>
    request<Incident>(`/api/incidents/${incidentId}/alerts/${alertId}`, { method: 'POST' }),
  removeAlertFromIncident: (incidentId: number, alertId: number) =>
    request<{ status: string }>(`/api/incidents/${incidentId}/alerts/${alertId}`, { method: 'DELETE' }),
  techniques: () => request<Technique[]>('/api/mitre/techniques'),
  incidentTechniques: (id: number) =>
    request<{ incident_id: number; techniques: Technique[] }>(`/api/mitre/incidents/${id}`),
  addTechnique: (incidentId: number, techniqueId: string) =>
    request<{ incident_id: number; techniques: Technique[] }>(
      `/api/incidents/${incidentId}/techniques/${encodeURIComponent(techniqueId)}`, { method: 'POST' },
    ),
  removeTechnique: (incidentId: number, techniqueId: string) =>
    request<{ incident_id: number; techniques: Technique[] }>(
      `/api/incidents/${incidentId}/techniques/${encodeURIComponent(techniqueId)}`, { method: 'DELETE' },
    ),
}
