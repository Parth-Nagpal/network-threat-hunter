import { useCallback, useEffect, useMemo, useState, type FormEvent, type ReactNode } from 'react'
import './App.css'
import {
  api,
  type Alert,
  type AlertStatus,
  type Incident,
  type InvestigationAction,
  type Severity,
  type Technique,
  type TelemetryEvent,
} from './api'

type Page = 'Dashboard' | 'Alerts' | 'Threat Hunting' | 'Incidents' | 'Investigation' | 'MITRE ATT&CK' | 'Hosts' | 'Reports'
const NAV: { name: Page; icon: string; section: string }[] = [
  { name: 'Dashboard', icon: '▦', section: 'WORKSPACE' },
  { name: 'Alerts', icon: '◈', section: 'WORKSPACE' },
  { name: 'Threat Hunting', icon: '⌕', section: 'WORKSPACE' },
  { name: 'Incidents', icon: '◎', section: 'RESPONSE' },
  { name: 'Investigation', icon: '⌖', section: 'RESPONSE' },
  { name: 'MITRE ATT&CK', icon: '▧', section: 'INTELLIGENCE' },
  { name: 'Hosts', icon: '▤', section: 'INTELLIGENCE' },
  { name: 'Reports', icon: '▥', section: 'INTELLIGENCE' },
]

function formatTime(value?: string) {
  if (!value) return '—'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })
}

function badgeClass(value?: string) {
  return `badge badge-${(value || 'unknown').toLowerCase().replaceAll('_', '-')}`
}

function Badge({ value }: { value?: string }) {
  return <span className={badgeClass(value)}>{(value || 'unknown').replaceAll('_', ' ')}</span>
}

function Panel({ title, subtitle, action, children, className = '' }: {
  title: string; subtitle?: string; action?: ReactNode; children: ReactNode; className?: string
}) {
  return <section className={`panel ${className}`}>
    <div className="panel-heading"><div><h2>{title}</h2>{subtitle && <p>{subtitle}</p>}</div>{action}</div>
    {children}
  </section>
}

function StateMessage({ loading, error, empty, onRetry }: { loading?: boolean; error?: string; empty?: string; onRetry?: () => void }) {
  if (loading) return <div className="state-message"><span className="spinner" />Loading data…</div>
  if (error) return <div className="state-message state-error"><span>{error}</span>{onRetry && <button className="button button-secondary" onClick={onRetry}>Retry</button>}</div>
  if (empty) return <div className="state-message"><span className="empty-mark">—</span>{empty}</div>
  return null
}

function Evidence({ value }: { value?: string }) {
  if (!value) return <span className="muted">No evidence recorded</span>
  try { return <pre className="evidence-block">{JSON.stringify(JSON.parse(value), null, 2)}</pre> }
  catch { return <pre className="evidence-block">{value}</pre> }
}

function DashboardPage() {
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const load = useCallback(async () => {
    setLoading(true); setError('')
    try {
      const [alertRows, incidentRows] = await Promise.all([api.allAlerts(), api.incidents()])
      setAlerts(alertRows); setIncidents(incidentRows)
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Unable to load dashboard data') }
    finally { setLoading(false) }
  }, [])
  useEffect(() => { void load() }, [load])
  const counts = useMemo(() => ({
    open: alerts.filter((item) => item.status === 'open').length,
    investigating: alerts.filter((item) => item.status === 'investigating').length,
    resolved: alerts.filter((item) => item.status === 'resolved').length,
    critical: alerts.filter((item) => item.severity === 'critical').length,
    high: alerts.filter((item) => item.severity === 'high').length,
    medium: alerts.filter((item) => item.severity === 'medium').length,
    low: alerts.filter((item) => item.severity === 'low').length,
  }), [alerts])
  const maxSeverity = Math.max(1, counts.critical, counts.high, counts.medium, counts.low)
  const activeIncidents = incidents.filter((item) => item.status === 'open' || item.status === 'investigating')
  return <>
    <div className="page-intro"><div><p className="eyebrow">OVERVIEW</p><h2>Security operations</h2><p className="muted">A live view of alert and incident data from your network sensor.</p></div><button className="button button-secondary" onClick={() => void load()}>↻ Refresh</button></div>
    <StateMessage loading={loading} error={error} onRetry={() => void load()} />
    {!loading && !error && <>
      <div className="metric-grid">
        <Metric title="Alerts loaded" value={alerts.length} hint="All pages from the alerts API" icon="◈" />
        <Metric title="Open" value={counts.open} hint="Alerts awaiting triage" tone="amber" icon="○" />
        <Metric title="Investigating" value={counts.investigating} hint="Alerts in active review" tone="blue" icon="⌕" />
        <Metric title="Active incidents" value={activeIncidents.length} hint="Open or investigating" tone="violet" icon="◎" />
      </div>
      <div className="dashboard-grid">
        <Panel title="Severity breakdown" subtitle="Across the alerts returned by the API">
          <div className="severity-chart">
            {(['critical', 'high', 'medium', 'low'] as const).map((severity) => <div className="severity-row" key={severity}>
              <div className="severity-label"><Badge value={severity} /><span>{counts[severity]}</span></div>
              <div className="bar-track"><div className={`bar-fill bar-${severity}`} style={{ width: `${counts[severity] / maxSeverity * 100}%` }} /></div>
            </div>)}
          </div>
          <div className="panel-foot">Resolved alerts: <strong>{counts.resolved}</strong></div>
        </Panel>
        <Panel title="Active incidents" subtitle={`${activeIncidents.length} from the incidents API`} action={<span className="live-dot-label"><i /> LIVE DATA</span>}>
          {activeIncidents.length === 0 ? <div className="empty-inline">No active incidents</div> : <div className="compact-list">
            {activeIncidents.slice(0, 5).map((item) => <div className="compact-item" key={item.id}><div><strong>{item.title}</strong><small>INC-{item.id} · {formatTime(item.updated_at)}</small></div><Badge value={item.severity} /></div>)}
          </div>}
        </Panel>
        <Panel title="Recent alerts" subtitle="Latest alert records" className="span-two">
          <AlertTable alerts={alerts.slice(0, 6)} />
        </Panel>
        <Panel title="Recent detection activity" subtitle="Detection rules represented by recent alerts" className="span-two">
          {alerts.length === 0 ? <div className="empty-inline">No alert activity has been recorded.</div> : <div className="activity-list">
            {alerts.slice(0, 6).map((alert) => <div className="activity-item" key={alert.id}><span className="activity-icon">⌁</span><div><strong>{alert.rule_name}</strong><small>{alert.src_ip} → {alert.dst_ip}</small></div><time>{formatTime(alert.timestamp)}</time></div>)}
          </div>}
        </Panel>
      </div><p className="dashboard-footnote">Alert totals include all alert API pages. Active incident count is from the latest 500 incidents returned by the API.</p>
    </>}
  </>
}

function Metric({ title, value, hint, icon, tone = 'cyan' }: { title: string; value: number; hint: string; icon: string; tone?: string }) {
  return <div className={`metric-card metric-${tone}`}><div className="metric-top"><span>{title}</span><span className="metric-icon">{icon}</span></div><strong>{value.toLocaleString()}</strong><small>{hint}</small></div>
}

function AlertTable({ alerts, onSelect }: { alerts: Alert[]; onSelect?: (alert: Alert) => void }) {
  if (!alerts.length) return <div className="empty-inline">No alerts match these filters.</div>
  return <div className="table-scroll"><table><thead><tr><th>Alert</th><th>Severity</th><th>Status</th><th>Source</th><th>Destination</th><th>Time</th></tr></thead><tbody>
    {alerts.map((alert) => <tr key={alert.id} className={onSelect ? 'clickable-row' : ''} onClick={() => onSelect?.(alert)}>
      <td><strong>{alert.rule_name}</strong><small className="cell-sub">ALT-{alert.id}</small></td><td><Badge value={alert.severity} /></td><td><Badge value={alert.status} /></td><td className="mono">{alert.src_ip}</td><td className="mono">{alert.dst_ip}</td><td>{formatTime(alert.timestamp)}</td>
    </tr>)}
  </tbody></table></div>
}

function AlertsPage() {
  const [filters, setFilters] = useState({ severity: '', type: '', status: '' })
  const [applied, setApplied] = useState({ severity: '', type: '', status: '' })
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [selected, setSelected] = useState<Alert | null>(null)
  const [selectedLoading, setSelectedLoading] = useState(false)
  const [selectedError, setSelectedError] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [skip, setSkip] = useState(0)
  const load = useCallback(async () => {
    setLoading(true); setError('')
    try { setAlerts(await api.alerts({ ...applied, skip, limit: 100 })) }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'Unable to load alerts') }
    finally { setLoading(false) }
  }, [applied, skip])
  useEffect(() => { void load() }, [load])
  useEffect(() => {
    if (!selected) return
    setSelectedLoading(true); setSelectedError('')
    api.alert(selected.id).then(setSelected).catch((cause) => setSelectedError(cause instanceof Error ? cause.message : 'Unable to load alert details')).finally(() => setSelectedLoading(false))
  // Refresh the detail only when another alert is selected; status updates set it directly.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected?.id])
  function submit(event: FormEvent) { event.preventDefault(); setSkip(0); setApplied(filters) }
  async function changeStatus(status: AlertStatus) {
    if (!selected) return
    try { const updated = await api.updateAlertStatus(selected.id, status); setSelected(updated); await load() }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'Unable to update alert status') }
  }
  return <>
    <div className="page-intro"><div><p className="eyebrow">TRIAGE</p><h2>Alerts</h2><p className="muted">Review detection findings, evidence, and response status.</p></div><button className="button button-secondary" onClick={() => void load()}>↻ Refresh</button></div>
    <Panel title="Filter alerts" subtitle="Filters are applied by the API">
      <form className="filter-row" onSubmit={submit}>
        <label>Severity<select value={filters.severity} onChange={(e) => setFilters({ ...filters, severity: e.target.value })}><option value="">All severities</option>{['critical', 'high', 'medium', 'low'].map((value) => <option key={value}>{value}</option>)}</select></label>
        <label>Type<input value={filters.type} onChange={(e) => setFilters({ ...filters, type: e.target.value })} placeholder="e.g. Port Scan" /></label>
        <label>Status<select value={filters.status} onChange={(e) => setFilters({ ...filters, status: e.target.value })}><option value="">All statuses</option>{['open', 'investigating', 'resolved', 'false_positive'].map((value) => <option key={value} value={value}>{value.replace('_', ' ')}</option>)}</select></label>
        <button className="button button-primary" type="submit">Apply filters</button>
      </form>
    </Panel>
    <Panel title="Alert queue" subtitle={loading ? 'Loading…' : `${alerts.length} results on this page`} action={<div className="pager"><button className="button button-quiet" disabled={skip === 0 || loading} onClick={() => setSkip(Math.max(0, skip - 100))}>← Previous</button><button className="button button-quiet" disabled={alerts.length < 100 || loading} onClick={() => setSkip(skip + 100)}>Next →</button></div>}>
      {error && <StateMessage error={error} onRetry={() => void load()} />}{!error && loading && <StateMessage loading />}{!error && !loading && <AlertTable alerts={alerts} onSelect={setSelected} />}
    </Panel>
    {selected && <div className="modal-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) setSelected(null) }}><aside className="detail-drawer">
      <div className="drawer-top"><div><p className="eyebrow">ALERT {selected.id}</p><h2>{selected.rule_name}</h2></div><button className="icon-button" aria-label="Close alert details" onClick={() => setSelected(null)}>×</button></div>
      <div className="drawer-badges"><Badge value={selected.severity} /><Badge value={selected.status} /></div>
      {selectedLoading && <StateMessage loading />}{selectedError && <StateMessage error={selectedError} />}
      <p className="detail-description">{selected.description}</p>
      <dl className="detail-grid"><dt>Source IP</dt><dd className="mono">{selected.src_ip}</dd><dt>Destination</dt><dd className="mono">{selected.dst_ip}</dd><dt>Detected</dt><dd>{formatTime(selected.timestamp)}</dd><dt>Created</dt><dd>{formatTime(selected.created_at)}</dd></dl>
      <h3>Detection evidence</h3><Evidence value={selected.evidence} />
      <label className="drawer-status">Update status<select value={selected.status} onChange={(e) => void changeStatus(e.target.value as AlertStatus)}>{['open', 'investigating', 'resolved', 'false_positive'].map((value) => <option key={value} value={value}>{value.replace('_', ' ')}</option>)}</select></label>
    </aside></div>}
  </>
}

function HuntPage() {
  const [filters, setFilters] = useState({ source_ip: '', destination_ip: '', source_port: '', destination_port: '', protocol: '', timestamp_from: '', timestamp_to: '', limit: '100' })
  const [events, setEvents] = useState<TelemetryEvent[]>([])
  const [loading, setLoading] = useState(false)
  const [searched, setSearched] = useState(false)
  const [error, setError] = useState('')
  async function search(event?: FormEvent) {
    event?.preventDefault(); setLoading(true); setError(''); setSearched(true)
    try {
      const params = { ...filters, timestamp_from: filters.timestamp_from || undefined, timestamp_to: filters.timestamp_to || undefined }
      setEvents(await api.hunt(params))
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Unable to search telemetry') }
    finally { setLoading(false) }
  }
  return <>
    <div className="page-intro"><div><p className="eyebrow">TELEMETRY SEARCH</p><h2>Threat Hunting</h2><p className="muted">Pivot across normalized connection, DNS, HTTP, and TLS events.</p></div></div>
    <Panel title="Search criteria" subtitle="The backend applies each filter before returning results">
      <form className="hunt-form" onSubmit={(e) => void search(e)}>
        <label>Source IP<input value={filters.source_ip} onChange={(e) => setFilters({ ...filters, source_ip: e.target.value })} placeholder="10.0.0.12" /></label>
        <label>Destination IP<input value={filters.destination_ip} onChange={(e) => setFilters({ ...filters, destination_ip: e.target.value })} placeholder="203.0.113.10" /></label>
        <label>Source port<input type="number" min="0" max="65535" value={filters.source_port} onChange={(e) => setFilters({ ...filters, source_port: e.target.value })} placeholder="Any" /></label>
        <label>Destination port<input type="number" min="0" max="65535" value={filters.destination_port} onChange={(e) => setFilters({ ...filters, destination_port: e.target.value })} placeholder="Any" /></label>
        <label>Protocol<input value={filters.protocol} onChange={(e) => setFilters({ ...filters, protocol: e.target.value })} placeholder="tcp, udp, dns" /></label>
        <label>From<input type="datetime-local" value={filters.timestamp_from} onChange={(e) => setFilters({ ...filters, timestamp_from: e.target.value })} /></label>
        <label>To<input type="datetime-local" value={filters.timestamp_to} onChange={(e) => setFilters({ ...filters, timestamp_to: e.target.value })} /></label>
        <label>Result limit<select value={filters.limit} onChange={(e) => setFilters({ ...filters, limit: e.target.value })}>{[25, 50, 100, 250, 500].map((value) => <option key={value}>{value}</option>)}</select></label>
        <div className="hunt-submit"><button className="button button-primary" type="submit">⌕ Search telemetry</button></div>
      </form>
    </Panel>
    <Panel title="Telemetry results" subtitle={searched && !loading && !error ? `${events.length} event${events.length === 1 ? '' : 's'} returned` : 'Results are sorted newest first'} action={searched && <button className="button button-secondary" onClick={() => void search()}>↻ Refresh</button>}>
      {error && <StateMessage error={error} onRetry={() => void search()} />}
      {!error && loading && <StateMessage loading />}
      {!error && !loading && !searched && <StateMessage empty="Set one or more filters, then search the telemetry store." />}
      {!error && !loading && searched && !events.length && <StateMessage empty="No telemetry matched this search." />}
      {!error && !loading && events.length > 0 && <TelemetryTable events={events} />}
    </Panel>
  </>
}

function TelemetryTable({ events }: { events: TelemetryEvent[] }) {
  return <div className="table-scroll"><table><thead><tr><th>Timestamp</th><th>Event</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Details</th></tr></thead><tbody>
    {events.map((event, index) => <tr key={`${event.event_type}-${event.id}-${index}`}><td>{formatTime(event.timestamp)}</td><td><span className="event-type">{event.event_type}</span></td><td className="mono">{event.source_ip}{event.source_port !== null ? `:${event.source_port}` : ''}</td><td className="mono">{event.destination_ip}{event.destination_port !== null ? `:${event.destination_port}` : ''}</td><td>{event.protocol}</td><td><span className="truncate" title={JSON.stringify(event.details)}>{Object.entries(event.details).filter(([, value]) => value !== null).slice(0, 2).map(([key, value]) => `${key}: ${String(value)}`).join(' · ') || '—'}</span></td></tr>)}
  </tbody></table></div>
}

function IncidentsPage() {
  return <IncidentWorkspace title="Incidents" subtitle="Correlated cases and response tracking" />
}

function InvestigationPage() {
  return <IncidentWorkspace title="Investigation" subtitle="Evidence pivots, analyst notes, and actions" />
}

function IncidentWorkspace({ title, subtitle }: { title: string; subtitle: string }) {
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [selectedId, setSelectedId] = useState<number | null>(null)
  const [investigation, setInvestigation] = useState<Incident | null>(null)
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [techniques, setTechniques] = useState<Technique[]>([])
  const [loading, setLoading] = useState(true)
  const [detailLoading, setDetailLoading] = useState(false)
  const [error, setError] = useState('')
  const [detailError, setDetailError] = useState('')
  const [noteText, setNoteText] = useState('')
  const [actionType, setActionType] = useState<InvestigationAction['action_type']>('reviewed')
  const [actionComment, setActionComment] = useState('')
  const [alertToAdd, setAlertToAdd] = useState('')
  const [techniqueToAdd, setTechniqueToAdd] = useState('')
  const [busy, setBusy] = useState(false)
  const loadList = useCallback(async () => {
    setLoading(true); setError('')
    try {
      const [incidentRows, alertRows, techniqueRows] = await Promise.all([api.incidents(), api.alerts({ limit: 500 }), api.techniques()])
      setIncidents(incidentRows); setAlerts(alertRows); setTechniques(techniqueRows)
      if (selectedId === null && incidentRows.length) setSelectedId(incidentRows[0].id)
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Unable to load incidents') }
    finally { setLoading(false) }
  }, [selectedId])
  const loadDetail = useCallback(async () => {
    if (selectedId === null) { setInvestigation(null); return }
    setDetailLoading(true); setDetailError('')
    try { setInvestigation(await api.investigation(selectedId)) }
    catch (cause) { setDetailError(cause instanceof Error ? cause.message : 'Unable to load investigation') }
    finally { setDetailLoading(false) }
  }, [selectedId])
  useEffect(() => { void loadList() }, [loadList])
  useEffect(() => { void loadDetail() }, [loadDetail])
  async function refresh() { await Promise.all([loadList(), loadDetail()]) }
  async function mutate(task: () => Promise<unknown>) {
    setBusy(true); setDetailError('')
    try { await task(); await refresh() }
    catch (cause) { setDetailError(cause instanceof Error ? cause.message : 'Action failed') }
    finally { setBusy(false) }
  }
  const associatedAlertIds = new Set(investigation?.alerts?.map((alert) => alert.id) || [])
  const availableAlerts = alerts.filter((alert) => !associatedAlertIds.has(alert.id))
  const associatedTechniques = investigation?.mitre_techniques || []
  const availableTechniques = techniques.filter((technique) => !associatedTechniques.some((item) => item.technique_id === technique.technique_id))
  const automaticTechniqueIds = new Set(associatedTechniques.filter((technique) =>
    technique.source_detection_type.split(',').some((name) => investigation?.alerts?.some((alert) => alert.type === name.trim())),
  ).map((technique) => technique.technique_id))
  const alertsTimeline = investigation?.timeline || []
  return <>
    <div className="page-intro"><div><p className="eyebrow">CASE MANAGEMENT</p><h2>{title}</h2><p className="muted">{subtitle}</p></div><button className="button button-secondary" onClick={() => void refresh()}>↻ Refresh</button></div>
    {error && <StateMessage error={error} onRetry={() => void loadList()} />}
    {!error && loading && <StateMessage loading />}
    {!error && !loading && <div className="incident-layout">
      <Panel title="Incident queue" subtitle={`${incidents.length} cases`} className="incident-queue">
        {incidents.length === 0 ? <div className="empty-inline">No incidents are available. Correlate open alerts through the API to create a case.</div> : <div className="incident-list">
          {incidents.map((incident) => <button key={incident.id} className={`incident-list-item ${selectedId === incident.id ? 'selected' : ''}`} onClick={() => setSelectedId(incident.id)}>
            <span className="incident-list-top"><strong>{incident.title}</strong><Badge value={incident.severity} /></span><span className="incident-list-meta">INC-{incident.id} · {formatTime(incident.updated_at)}</span><span className="incident-list-status"><Badge value={incident.status} /></span>
          </button>)}
        </div>}
      </Panel>
      <div className="incident-detail-column">
        {detailError && <StateMessage error={detailError} onRetry={() => void loadDetail()} />}
        {detailLoading && <Panel title="Incident detail"><StateMessage loading /></Panel>}
        {!detailLoading && !detailError && !investigation && <Panel title="Incident detail"><StateMessage empty="Select an incident to review its evidence." /></Panel>}
        {!detailLoading && !detailError && investigation && <>
          <Panel title={investigation.title} subtitle={`INC-${investigation.id} · Created ${formatTime(investigation.created_at)}`} action={<Badge value={investigation.status} />}>
            <p className="incident-summary">{investigation.summary || 'No incident summary provided.'}</p>
            <div className="inline-fields"><label>Severity<select value={investigation.severity} disabled={busy} onChange={(e) => void mutate(() => api.updateIncident(investigation.id, { severity: e.target.value as Severity }))}>{['critical', 'high', 'medium', 'low'].map((value) => <option key={value}>{value}</option>)}</select></label><label>Status<select value={investigation.status} disabled={busy} onChange={(e) => void mutate(() => api.updateIncident(investigation.id, { status: e.target.value as AlertStatus }))}>{['open', 'investigating', 'resolved', 'false_positive'].map((value) => <option key={value} value={value}>{value.replace('_', ' ')}</option>)}</select></label></div>
          </Panel>
          <Panel title="Associated alerts" subtitle={`${investigation.alerts?.length || 0} linked alert records`}>
            {(investigation.alerts || []).length === 0 ? <div className="empty-inline">No alerts are associated with this incident.</div> : <div className="associated-list">{investigation.alerts?.map((alert) => <div className="associated-row" key={alert.id}><div><strong>{alert.rule_name}</strong><small>{alert.source_ip} → {alert.destination_ip} · {formatTime(alert.timestamp)}</small></div><Badge value={alert.severity} /><button className="text-button danger-text" disabled={busy} onClick={() => void mutate(() => api.removeAlertFromIncident(investigation.id, alert.id))}>Remove</button></div>)}</div>}
            <div className="association-add"><select aria-label="Alert to add" value={alertToAdd} onChange={(e) => setAlertToAdd(e.target.value)}><option value="">Select an alert to associate</option>{availableAlerts.map((alert) => <option key={alert.id} value={alert.id}>ALT-{alert.id} · {alert.rule_name} · {alert.src_ip}</option>)}</select><button className="button button-secondary" disabled={!alertToAdd || busy} onClick={() => void mutate(async () => { await api.addAlertToIncident(investigation.id, Number(alertToAdd)); setAlertToAdd('') })}>Add alert</button></div>
          </Panel>
          <Panel title="Chronological timeline" subtitle="Alert evidence preserved from detection">
            {alertsTimeline.length === 0 ? <div className="empty-inline">No alert timeline entries.</div> : <div className="timeline">{alertsTimeline.map((item, index) => <div className="timeline-item" key={`${item.timestamp}-${index}`}><div className="timeline-marker" /><div className="timeline-content"><div className="timeline-title"><strong>{item.rule_name}</strong><Badge value={item.severity} /></div><small>{formatTime(item.timestamp)} · {item.source_ip} → {item.destination_ip}</small><Evidence value={item.evidence} /></div></div>)}</div>}
          </Panel>
          <Panel title="Related telemetry" subtitle="IP-pivoted events inside the investigation time window">
            {(investigation.related_telemetry || []).length ? <TelemetryTable events={investigation.related_telemetry || []} /> : <div className="empty-inline">No related telemetry was found for the associated alert IPs and time window.</div>}
          </Panel>
          <Panel title="Indicators of compromise" subtitle="Extracted from associated alert evidence and related telemetry">
            <div className="ioc-grid">{[
              ['IP addresses', investigation.iocs?.ip_addresses || []], ['Domains', investigation.iocs?.domains || []], ['URLs', investigation.iocs?.urls || []], ['Destination ports', investigation.iocs?.destination_ports || []],
            ].map(([label, values]) => <div className="ioc-group" key={String(label)}><h3>{String(label)} <span>{(values as unknown[]).length}</span></h3>{(values as (string | number)[]).length ? (values as (string | number)[]).map((value) => <code key={value}>{value}</code>) : <small className="muted">None extracted</small>}</div>)}</div>
          </Panel>
          <Panel title="MITRE ATT&CK techniques" subtitle="Alert-derived mappings and manually associated techniques">
            {associatedTechniques.length === 0 ? <div className="empty-inline">No techniques are mapped to this incident.</div> : <div className="technique-list">{associatedTechniques.map((technique) => <div className="technique-row" key={technique.technique_id}><div><strong>{technique.technique_id} · {technique.name}</strong><small>{technique.tactic} · {technique.source_detection_type}</small></div>{!automaticTechniqueIds.has(technique.technique_id) && <button className="text-button danger-text" disabled={busy} onClick={() => void mutate(() => api.removeTechnique(investigation.id, technique.technique_id))}>Remove</button>}</div>)}</div>}
            <div className="association-add"><select aria-label="Technique to add" value={techniqueToAdd} onChange={(e) => setTechniqueToAdd(e.target.value)}><option value="">Select a technique</option>{availableTechniques.map((technique) => <option key={technique.technique_id} value={technique.technique_id}>{technique.technique_id} · {technique.name}</option>)}</select><button className="button button-secondary" disabled={!techniqueToAdd || busy} onClick={() => void mutate(async () => { await api.addTechnique(investigation.id, techniqueToAdd); setTechniqueToAdd('') })}>Add technique</button></div>
          </Panel>
          <div className="workspace-columns">
            <Panel title="Analyst notes" subtitle="Notes are stored separately from alert evidence">
              {(investigation.notes || []).map((note) => <div className="note-card" key={note.id}><p>{note.content}</p><small>{formatTime(note.created_at)}</small><button className="text-button danger-text" disabled={busy} onClick={() => void mutate(() => api.deleteNote(investigation.id, note.id))}>Delete</button></div>)}
              <form className="stack-form" onSubmit={(e) => { e.preventDefault(); if (noteText.trim()) void mutate(async () => { await api.addNote(investigation.id, noteText.trim()); setNoteText('') }) }}><label>Add a note<textarea value={noteText} onChange={(e) => setNoteText(e.target.value)} rows={3} placeholder="Record an observation or handoff…" /></label><button className="button button-primary" disabled={!noteText.trim() || busy}>Save note</button></form>
            </Panel>
            <Panel title="Investigation actions" subtitle="Record analyst workflow actions">
              {(investigation.actions || []).map((action) => <div className="action-item" key={action.id}><Badge value={action.action_type} /><span>{action.comment || 'No comment'}</span><small>{formatTime(action.created_at)}</small></div>)}
              <form className="stack-form" onSubmit={(e) => { e.preventDefault(); void mutate(async () => { await api.addAction(investigation.id, actionType, actionComment.trim()); setActionComment('') }) }}><label>Action<select value={actionType} onChange={(e) => setActionType(e.target.value as InvestigationAction['action_type'])}>{['reviewed', 'marked_suspicious', 'marked_benign', 'escalated'].map((value) => <option key={value} value={value}>{value.replaceAll('_', ' ')}</option>)}</select></label><label>Comment<input value={actionComment} onChange={(e) => setActionComment(e.target.value)} placeholder="Optional context" /></label><button className="button button-primary" disabled={busy}>Record action</button></form>
            </Panel>
          </div>
        </>}
      </div>
    </div>}
  </>
}

function MitrePage() {
  const [techniques, setTechniques] = useState<Technique[]>([])
  const [associated, setAssociated] = useState<Record<string, Incident[]>>({})
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const load = useCallback(async () => {
    setLoading(true); setError('')
    try {
      const [techniqueRows, incidentRows] = await Promise.all([api.techniques(), api.incidents(100)])
      setTechniques(techniqueRows)
      const matches: Record<string, Incident[]> = Object.fromEntries(techniqueRows.map((technique) => [technique.technique_id, []]))
      for (let index = 0; index < incidentRows.length; index += 10) {
        const batch = incidentRows.slice(index, index + 10)
        const mappings = await Promise.all(batch.map((incident) => api.incidentTechniques(incident.id)))
        mappings.forEach((mapping, offset) => mapping.techniques.forEach((technique) => {
          matches[technique.technique_id]?.push(batch[offset])
        }))
      }
      setAssociated(matches)
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Unable to load MITRE mappings') }
    finally { setLoading(false) }
  }, [])
  useEffect(() => { void load() }, [load])
  return <>
    <div className="page-intro"><div><p className="eyebrow">KNOWLEDGE BASE</p><h2>MITRE ATT&CK</h2><p className="muted">Deterministic detection mappings and incident coverage.</p></div><button className="button button-secondary" onClick={() => void load()}>↻ Refresh</button></div>
    {error && <StateMessage error={error} onRetry={() => void load()} />}{loading && <StateMessage loading />}
    {!loading && !error && <><div className="mitre-summary"><span className="metric-icon">▧</span><div><strong>{techniques.length} mapped techniques</strong><small>Showing incident associations for the latest 100 incidents.</small></div></div>
      {techniques.length === 0 ? <Panel title="Technique catalog"><StateMessage empty="No MITRE techniques are available from the API." /></Panel> : <div className="technique-grid">{techniques.map((technique) => <Panel key={technique.technique_id} title={technique.name} subtitle={technique.tactic} className="technique-card"><div className="technique-id">{technique.technique_id}</div><p>{technique.description}</p><div className="technique-source"><span>Mapped from</span><strong>{technique.source_detection_type}</strong></div><div className="technique-incidents"><h3>Associated incidents <span>{associated[technique.technique_id]?.length || 0}</span></h3>{(associated[technique.technique_id] || []).length ? associated[technique.technique_id].map((incident) => <div className="technique-incident" key={incident.id}><span>INC-{incident.id} · {incident.title}</span><Badge value={incident.severity} /></div>) : <small className="muted">No associated incidents in the checked set.</small>}</div></Panel>)}</div>}
    </>}
  </>
}

function PlaceholderPage({ title }: { title: string }) {
  return <div className="placeholder-page"><div className="placeholder-icon">⌁</div><p className="eyebrow">NOT AVAILABLE</p><h2>{title}</h2><p>This workspace is reserved for {title.toLowerCase()} data. The current backend does not expose a supporting API yet.</p><span className="placeholder-tag">Backend integration pending</span></div>
}

function App() {
  const [page, setPage] = useState<Page>('Dashboard')
  const [health, setHealth] = useState<'healthy' | 'unhealthy' | 'loading'>('loading')
  const [mobileNavOpen, setMobileNavOpen] = useState(false)
  const [healthError, setHealthError] = useState('')
  const refreshHealth = useCallback(async () => {
    setHealth('loading'); setHealthError('')
    try { const result = await api.health(); setHealth(result.status === 'healthy' ? 'healthy' : 'unhealthy') }
    catch (cause) { setHealth('unhealthy'); setHealthError(cause instanceof Error ? cause.message : 'API unavailable') }
  }, [])
  useEffect(() => { void refreshHealth() }, [refreshHealth])
  function navigate(next: Page) { setPage(next); setMobileNavOpen(false) }
  return <div className="app-shell">
    <aside className={`sidebar ${mobileNavOpen ? 'sidebar-open' : ''}`}>
      <div className="brand"><div className="brand-mark"><span>TH</span><i /></div><div><strong>THREAT<span>HUNTER</span></strong><small>NETWORK DEFENSE</small></div></div>
      <div className="sensor-card"><span className={`sensor-indicator ${health}`} /><div><strong>Network sensor</strong><small>{health === 'loading' ? 'Checking connection' : health === 'healthy' ? 'API connected' : 'API unavailable'}</small></div><button className="mini-refresh" aria-label="Refresh API health" onClick={() => void refreshHealth()}>↻</button></div>
      {['WORKSPACE', 'RESPONSE', 'INTELLIGENCE'].map((section) => <div className="nav-section" key={section}><p>{section}</p>{NAV.filter((item) => item.section === section).map((item) => <button key={item.name} className={`nav-item ${page === item.name ? 'nav-active' : ''}`} onClick={() => navigate(item.name)}><span className="nav-icon">{item.icon}</span><span>{item.name}</span></button>)}</div>)}
      <div className="sidebar-footer"><div className="footer-avatar">SOC</div><div><strong>Analyst workspace</strong><small>Local deployment</small></div></div>
    </aside>
    {mobileNavOpen && <button className="mobile-scrim" aria-label="Close navigation" onClick={() => setMobileNavOpen(false)} />}
    <main className="main-area"><header className="topbar"><button className="mobile-menu" onClick={() => setMobileNavOpen(!mobileNavOpen)} aria-label="Toggle navigation">☰</button><div className="breadcrumb"><span>Network Threat Hunter</span><b>/</b><strong>{page}</strong></div><div className="topbar-right"><span className="utc-label">SOC CONSOLE</span><button className="top-health" onClick={() => void refreshHealth()}><i className={`sensor-indicator ${health}`} />{health === 'loading' ? 'Connecting' : health === 'healthy' ? 'System operational' : 'Backend offline'}</button></div></header>
      {healthError && <div className="global-api-error"><span>{healthError}</span><button onClick={() => void refreshHealth()}>Retry</button></div>}
      <div className="page-content">{page === 'Dashboard' && <DashboardPage />}{page === 'Alerts' && <AlertsPage />}{page === 'Threat Hunting' && <HuntPage />}{page === 'Incidents' && <IncidentsPage />}{page === 'Investigation' && <InvestigationPage />}{page === 'MITRE ATT&CK' && <MitrePage />}{(page === 'Hosts' || page === 'Reports') && <PlaceholderPage title={page} />}</div>
      <footer className="app-footer"><span>NETWORK THREAT HUNTER <i>·</i> SOC WORKSPACE</span><span>DATA FROM CONFIGURED BACKEND APIS</span></footer>
    </main>
  </div>
}

export default App
