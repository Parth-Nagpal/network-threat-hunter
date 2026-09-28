import { useCallback, useEffect, useMemo, useState, type FormEvent, type ReactNode } from 'react'
import './App.css'
import {
  api,
  type Alert,
  type AlertStatus,
  type Incident,
  type LabRun,
  type LabScenario,
  type InvestigationAction,
  type Severity,
  type Technique,
  type TelemetryEvent,
  type ReportPreview,
  type ReportRequest,
  type ReportIncidentRecord,
} from './api'

type Page = 'Dashboard' | 'Alerts' | 'Threat Hunting' | 'Attack Lab' | 'Incidents' | 'Investigation' | 'MITRE ATT&CK' | 'Hosts' | 'Reports' | 'Settings'
type Theme = 'dark' | 'light'
const NAV: { name: Page; icon: string; section: string }[] = [
  { name: 'Dashboard', icon: '▦', section: 'WORKSPACE' },
  { name: 'Alerts', icon: '◈', section: 'WORKSPACE' },
  { name: 'Threat Hunting', icon: '⌕', section: 'WORKSPACE' },
  { name: 'Attack Lab', icon: '⏵', section: 'WORKSPACE' },
  { name: 'Incidents', icon: '◎', section: 'RESPONSE' },
  { name: 'Investigation', icon: '⌖', section: 'RESPONSE' },
  { name: 'MITRE ATT&CK', icon: '▧', section: 'INTELLIGENCE' },
  { name: 'Hosts', icon: '▤', section: 'INTELLIGENCE' },
  { name: 'Reports', icon: '▥', section: 'INTELLIGENCE' },
  { name: 'Settings', icon: '⚙', section: 'SYSTEM' },
]

function formatTime(value?: string) {
  if (!value) return '—'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })
}

function parseAlertTimestamp(value: string) {
  // API timestamps without an explicit offset represent database UTC values.
  // Offset-aware values retain their supplied instant before local rendering.
  const hasOffset = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(value)
  const date = new Date(hasOffset ? value : `${value}Z`)
  return Number.isFinite(date.getTime()) ? date : null
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

const ALERT_SERIES = [
  { key: 'critical', label: 'Critical', color: '#c96b70' },
  { key: 'high', label: 'High', color: '#d18a50' },
  { key: 'medium', label: 'Medium', color: '#c7a653' },
  { key: 'low', label: 'Low', color: '#8878e8' },
] as const

function AlertsOverTime({ alerts }: { alerts: Alert[] }) {
  const points = alerts.flatMap((alert) => {
    if (typeof alert.timestamp !== 'string' || !alert.timestamp.trim()) return []
    const date = parseAlertTimestamp(alert.timestamp)
    return date ? [{ alert, time: date.getTime() }] : []
  }).sort((left, right) => left.time - right.time)
  if (!points.length) return <div className="chart-empty">No alert timestamps are available for this chart.</div>

  const earliest = points[0].time
  const latest = points[points.length - 1].time
  const span = latest - earliest
  const hour = 60 * 60 * 1000
  const day = 24 * hour
  const bucketSize = span <= 6 * hour ? hour : span <= 48 * hour ? 3 * hour : span <= 14 * day ? day : 7 * day
  const bucketKind = bucketSize === hour ? 'hour' : bucketSize === 3 * hour ? 'three-hour' : bucketSize === day ? 'day' : 'week'
  const bucketStart = (timestamp: number) => {
    const date = new Date(timestamp)
    if (bucketKind === 'hour') date.setMinutes(0, 0, 0)
    else if (bucketKind === 'three-hour') date.setHours(Math.floor(date.getHours() / 3) * 3, 0, 0, 0)
    else if (bucketKind === 'day') date.setHours(0, 0, 0, 0)
    else {
      date.setHours(0, 0, 0, 0)
      date.setDate(date.getDate() - ((date.getDay() + 6) % 7))
    }
    return date.getTime()
  }
  const nextBucket = (timestamp: number) => {
    const date = new Date(timestamp)
    if (bucketKind === 'hour') date.setHours(date.getHours() + 1)
    else if (bucketKind === 'three-hour') date.setHours(date.getHours() + 3)
    else if (bucketKind === 'day') date.setDate(date.getDate() + 1)
    else date.setDate(date.getDate() + 7)
    return date.getTime()
  }
  const start = bucketStart(earliest)
  const lastBucket = bucketStart(latest)
  const bins: { time: number; critical: number; high: number; medium: number; low: number }[] = []
  for (let time = start, count = 0; time <= lastBucket && count < 10000; time = nextBucket(time), count += 1) {
    bins.push({ time, critical: 0, high: 0, medium: 0, low: 0 })
  }
  const binIndexes = new Map(bins.map((bin, index) => [bin.time, index]))
  points.forEach(({ alert, time }) => {
    const index = binIndexes.get(bucketStart(time))
    const bin = index === undefined ? undefined : bins[index]
    const series = ALERT_SERIES.find((item) => item.key === alert.severity)
    if (bin && series) bin[series.key] += 1
  })

  const width = Math.max(920, bins.length * 38)
  const height = 280
  const pad = { top: 16, right: 18, bottom: 46, left: 42 }
  const plotWidth = width - pad.left - pad.right
  const plotHeight = height - pad.top - pad.bottom
  const maxCount = Math.max(1, ...bins.map((bin) => bin.critical + bin.high + bin.medium + bin.low))
  const barWidth = Math.min(24, Math.max(6, plotWidth / bins.length * 0.68))
  const tickStep = Math.max(1, Math.ceil(bins.length / Math.floor(plotWidth / 110)))
  const tickIndexes = bins.map((_, index) => index).filter((index) => index % tickStep === 0 || index === bins.length - 1)
  const tickLabel = (value: number) => bucketSize < 24 * hour
    ? new Date(value).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    : new Date(value).toLocaleDateString([], { month: 'short', day: 'numeric' })
  const tooltipTime = (value: number) => new Date(value).toLocaleString([], {
    day: '2-digit', month: 'short', hour: 'numeric', minute: '2-digit',
  })

  return <div className="alerts-chart-wrap">
    <div className="alerts-chart-legend">{ALERT_SERIES.map((series) => <span key={series.key}><i style={{ backgroundColor: series.color }} />{series.label}</span>)}</div>
    <svg className="alerts-chart" style={{ width: `max(100%, ${width}px)` }} viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Stacked alerts over time by severity">
      {[0, 0.33, 0.66, 1].map((fraction) => {
        const y = pad.top + plotHeight * fraction
        const value = Math.round(maxCount * (1 - fraction))
        return <g key={fraction}><line x1={pad.left} x2={width - pad.right} y1={y} y2={y} className="chart-gridline" /><text x={pad.left - 9} y={y + 3} textAnchor="end" className="chart-axis-label">{value}</text></g>
      })}
      {bins.map((bin, index) => {
        const x = pad.left + index * (plotWidth / bins.length) + (plotWidth / bins.length - barWidth) / 2
        let cumulative = 0
        return <g key={bin.time}>{ALERT_SERIES.map((series) => {
          const count = bin[series.key]
          if (!count) return null
          const segmentHeight = (count / maxCount) * plotHeight
          const y = pad.top + plotHeight - ((cumulative + count) / maxCount) * plotHeight
          cumulative += count
          const total = bin.critical + bin.high + bin.medium + bin.low
          const tooltip = `${tooltipTime(bin.time)}\nCritical: ${bin.critical}\nHigh: ${bin.high}\nMedium: ${bin.medium}\nLow: ${bin.low}\nTotal: ${total}`
          return <rect key={series.key} x={x} y={y} width={barWidth} height={Math.max(segmentHeight, 1)} fill={series.color} rx="1">
            <title>{tooltip}</title>
          </rect>
        })}</g>
      })}
      {tickIndexes.map((index) => {
        const x = pad.left + index * (plotWidth / bins.length) + plotWidth / bins.length / 2
        return <text key={index} x={x} y={height - 14} textAnchor="middle" className="chart-axis-label">{tickLabel(bins[index].time)}</text>
      })}
    </svg>
    <div className="chart-caption">{bucketSize === 7 * day ? 'Weekly' : bucketSize === day ? 'Daily' : bucketSize === hour ? 'Hourly' : `${bucketSize / hour}-hour`} buckets · based on available alert timestamps</div>
  </div>
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
      <Panel title="Alerts Over Time" subtitle="Alert volume by severity from the alert timestamps">
        {alerts.length ? <AlertsOverTime alerts={alerts} /> : <div className="chart-empty">No alerts are available for the selected data.</div>}
      </Panel>
      <div className="dashboard-grid dashboard-lower-grid">
        <Panel title="Recent alerts" subtitle="Latest alert records">
          <AlertTable alerts={alerts.slice(0, 6)} />
        </Panel>
        <Panel title="Recent incidents" subtitle={`${activeIncidents.length} open or investigating`}>
          {activeIncidents.length === 0 ? <div className="empty-inline">No active incidents</div> : <div className="compact-list">
            {activeIncidents.slice(0, 6).map((item) => <div className="compact-item" key={item.id}><div><strong>{item.title}</strong><small>INC-{item.id} · {formatTime(item.updated_at)}</small></div><Badge value={item.severity} /></div>)}
          </div>}
        </Panel>
        <Panel title="Recent detection activity" subtitle="Latest detection findings">
          {alerts.length === 0 ? <div className="empty-inline">No detection activity has been recorded.</div> : <div className="activity-list">
            {alerts.slice(0, 6).map((alert) => <div className="activity-item" key={alert.id}><span className="activity-icon">⌁</span><div><strong>{alert.rule_name}</strong><small>{alert.src_ip} → {alert.dst_ip}</small></div><time>{formatTime(alert.timestamp)}</time></div>)}
          </div>}
        </Panel>
      </div><p className="dashboard-footnote">Alert totals include all alert API pages. Recent incidents are from the latest 500 incidents returned by the API.</p>
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
    {events.map((event, index) => <tr key={`${event.event_type}-${event.id}-${index}`}><td>{formatTime(event.timestamp)}</td><td><span className="event-type">{event.event_type}</span>{event.is_simulated && <span className="simulation-tag">SIM</span>}</td><td className="mono">{event.source_ip}{event.source_port !== null ? `:${event.source_port}` : ''}</td><td className="mono">{event.destination_ip}{event.destination_port !== null ? `:${event.destination_port}` : ''}</td><td>{event.protocol}</td><td><span className="truncate" title={JSON.stringify(event.details)}>{Object.entries(event.details).filter(([, value]) => value !== null).slice(0, 2).map(([key, value]) => `${key}: ${String(value)}`).join(' · ') || '—'}</span></td></tr>)}
  </tbody></table></div>
}

function AttackLabPage({ onInvestigate }: { onInvestigate: (id: number) => void }) {
  const [scenarios, setScenarios] = useState<LabScenario[]>([])
  const [runs, setRuns] = useState<LabRun[]>([])
  const [selectedRun, setSelectedRun] = useState<LabRun | null>(null)
  const [running, setRunning] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const refresh = useCallback(async () => {
    setLoading(true); setError('')
    try {
      const [scenarioRows, runRows] = await Promise.all([api.labScenarios(), api.labRuns()])
      setScenarios(scenarioRows); setRuns(runRows)
      if (selectedRun) setSelectedRun(await api.labRun(selectedRun.id))
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Unable to load Attack Lab') }
    finally { setLoading(false) }
  }, [selectedRun])
  useEffect(() => { void refresh() }, [])
  async function runScenario(scenario: LabScenario) {
    setRunning(scenario.id); setError('')
    try {
      const run = await api.runLabScenario(scenario.id)
      setSelectedRun(run)
      const history = await api.labRuns()
      setRuns(history)
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Scenario run failed') }
    finally { setRunning(null) }
  }
  return <>
    <div className="page-intro"><div><p className="eyebrow">CONTROLLED SIMULATION</p><h2>Attack Lab</h2><p className="muted">Safe synthetic telemetry exercises the production detection, correlation, and investigation workflow.</p></div><button className="button button-secondary" onClick={() => void refresh()}>↻ Refresh</button></div>
    {error && <StateMessage error={error} onRetry={() => void refresh()} />}
    <Panel title="Available scenarios" subtitle="Local database records only · no packets, credentials, or external targets">
      {loading ? <StateMessage loading /> : <div className="lab-scenario-grid">{scenarios.map((scenario) => <article className="lab-scenario" key={scenario.id}><div className="lab-scenario-title"><h3>{scenario.name}</h3><span className="event-type">{scenario.detection}</span></div><p>{scenario.description}</p><small>{scenario.safety}</small><button className="button button-primary" disabled={running !== null} onClick={() => void runScenario(scenario)}>{running === scenario.id ? 'Running…' : '▶ Run simulation'}</button></article>)}</div>}
    </Panel>
    {selectedRun && <Panel title={`Run #${selectedRun.id} · ${selectedRun.scenario.name}`} subtitle={`Started ${formatTime(selectedRun.start_time)}`}>
      <div className="lab-run-summary"><Badge value={selectedRun.status} /><span>{selectedRun.generated_event_count} synthetic events</span><span>{selectedRun.alert_ids.length} alerts</span><span>{selectedRun.incident_ids.length} incidents</span></div>
      {(selectedRun.alerts || []).map((alert) => <div className="lab-result-row" key={alert.id}><span>ALT-{alert.id} · {alert.rule_name}</span><Badge value={alert.severity} /></div>)}
      {(selectedRun.incidents || []).map((incident) => <div className="lab-result-row" key={incident.id}><span>INC-{incident.id} · {incident.title} <Badge value={incident.severity} /></span><button className="button button-secondary" onClick={() => onInvestigate(incident.id)}>Investigate →</button></div>)}
      {selectedRun.generated_telemetry?.length ? <details className="lab-telemetry"><summary>Generated telemetry ({selectedRun.generated_telemetry.length})</summary><TelemetryTable events={selectedRun.generated_telemetry} /></details> : null}
    </Panel>}
    <Panel title="Run history" subtitle="Recent simulation runs" action={<button className="button button-secondary" onClick={() => void refresh()}>↻ Refresh</button>}>
      {!loading && !runs.length ? <StateMessage empty="No simulation runs yet." /> : <div className="table-scroll"><table><thead><tr><th>Scenario</th><th>Started</th><th>Status</th><th>Events</th><th>Alerts</th><th>Incidents</th><th /></tr></thead><tbody>{runs.map((run) => <tr key={run.id}><td>{run.scenario.name}</td><td>{formatTime(run.start_time)}</td><td><Badge value={run.status} /></td><td>{run.generated_event_count}</td><td>{run.alert_ids.length}</td><td>{run.incident_ids.length}</td><td><button className="text-button" onClick={async () => setSelectedRun(await api.labRun(run.id))}>View run</button></td></tr>)}</tbody></table></div>}
    </Panel>
  </>
}

function IncidentsPage() {
  return <IncidentWorkspace title="Incidents" subtitle="Correlated cases and response tracking" />
}

function InvestigationPage({ incidentId }: { incidentId: number | null }) {
  return <IncidentWorkspace title="Investigation" subtitle="Evidence pivots, analyst notes, and actions" initialIncidentId={incidentId} />
}

function IncidentWorkspace({ title, subtitle, initialIncidentId = null }: { title: string; subtitle: string; initialIncidentId?: number | null }) {
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [selectedId, setSelectedId] = useState<number | null>(initialIncidentId)
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

type RecentReport = Pick<ReportPreview, 'report_type' | 'generated_at' | 'record_count'>

function ReportsPage() {
  const [reportType, setReportType] = useState<ReportRequest['report_type']>('alerts')
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [severity, setSeverity] = useState('')
  const [status, setStatus] = useState('')
  const [alertType, setAlertType] = useState('')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')
  const [selectedAlerts, setSelectedAlerts] = useState<number[]>([])
  const [selectedIncidents, setSelectedIncidents] = useState<number[]>([])
  const [selectedOnly, setSelectedOnly] = useState(false)
  const [preview, setPreview] = useState<ReportPreview | null>(null)
  const [previewRequest, setPreviewRequest] = useState<ReportRequest | null>(null)
  const [recent, setRecent] = useState<RecentReport[]>(() => {
    try {
      const saved: unknown = JSON.parse(window.localStorage.getItem('threat-hunter-recent-reports') || '[]')
      return Array.isArray(saved) ? saved.slice(0, 8) as RecentReport[] : []
    } catch { return [] }
  })
  const [loading, setLoading] = useState(true)
  const [generating, setGenerating] = useState(false)
  const [downloading, setDownloading] = useState<'pdf' | 'docx' | null>(null)
  const [error, setError] = useState('')
  const [downloadError, setDownloadError] = useState('')

  const load = useCallback(async () => {
    setLoading(true); setError('')
    try {
      const [alertRows, incidentRows] = await Promise.all([api.allAlerts(), api.incidents(500)])
      setAlerts(alertRows); setIncidents(incidentRows)
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Unable to load report data') }
    finally { setLoading(false) }
  }, [])
  useEffect(() => { void load() }, [load])

  const alertTypes = useMemo(() => [...new Set(alerts.map((alert) => alert.alert_type))].sort(), [alerts])
  const visibleAlerts = useMemo(() => alerts.filter((alert) => {
    if (severity && alert.severity !== severity) return false
    if (status && alert.status !== status) return false
    if (alertType && alert.alert_type !== alertType) return false
    const timestamp = new Date(alert.timestamp).getTime()
    if (dateFrom && (!Number.isFinite(timestamp) || timestamp < new Date(`${dateFrom}T00:00:00`).getTime())) return false
    if (dateTo && (!Number.isFinite(timestamp) || timestamp > new Date(`${dateTo}T23:59:59`).getTime())) return false
    return true
  }), [alerts, severity, status, alertType, dateFrom, dateTo])
  const visibleIncidents = useMemo(() => incidents.filter((incident) => {
    if (severity && incident.severity !== severity) return false
    if (status && incident.status !== status) return false
    const timestamp = new Date(incident.created_at).getTime()
    if (dateFrom && (!Number.isFinite(timestamp) || timestamp < new Date(`${dateFrom}T00:00:00`).getTime())) return false
    if (dateTo && (!Number.isFinite(timestamp) || timestamp > new Date(`${dateTo}T23:59:59`).getTime())) return false
    return true
  }), [incidents, severity, status, dateFrom, dateTo])
  const visibleIds = reportType === 'alerts' ? visibleAlerts.map((alert) => alert.id) : visibleIncidents.map((incident) => incident.id)
  const currentSelection = reportType === 'alerts' ? selectedAlerts : selectedIncidents
  const allVisibleSelected = visibleIds.length > 0 && visibleIds.every((id) => currentSelection.includes(id))

  function buildPayload(): ReportRequest {
    const payload: ReportRequest = { report_type: reportType }
    if (severity) payload.severity = severity
    if (status) payload.status = status as AlertStatus
    if (dateFrom) payload.timestamp_from = new Date(`${dateFrom}T00:00:00`).toISOString()
    if (dateTo) payload.timestamp_to = new Date(`${dateTo}T23:59:59.999`).toISOString()
    if (reportType === 'alerts') {
      if (alertType) payload.alert_type = alertType
      if (selectedOnly) payload.alert_ids = selectedAlerts
    } else if (selectedOnly) payload.incident_ids = selectedIncidents
    return payload
  }

  async function generate() {
    const payload = buildPayload()
    setGenerating(true); setError(''); setDownloadError('')
    try {
      const result = await api.reportPreview(payload)
      setPreview(result); setPreviewRequest(payload)
      const next = [{ report_type: result.report_type, generated_at: result.generated_at, record_count: result.record_count }, ...recent].slice(0, 8)
      setRecent(next)
      window.localStorage.setItem('threat-hunter-recent-reports', JSON.stringify(next))
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Unable to generate report') }
    finally { setGenerating(false) }
  }

  async function download(format: 'pdf' | 'docx') {
    if (!previewRequest) return
    setDownloading(format); setDownloadError('')
    try {
      const file = await api.exportReport(previewRequest, format)
      const href = URL.createObjectURL(file.blob)
      const link = document.createElement('a')
      link.href = href; link.download = file.filename
      document.body.appendChild(link); link.click(); link.remove()
      URL.revokeObjectURL(href)
    } catch (cause) { setDownloadError(cause instanceof Error ? cause.message : `Unable to export ${format.toUpperCase()}`) }
    finally { setDownloading(null) }
  }

  function toggleVisible(checked: boolean) {
    const update = (current: number[]) => checked
      ? [...new Set([...current, ...visibleIds])]
      : current.filter((id) => !visibleIds.includes(id))
    if (reportType === 'alerts') setSelectedAlerts(update)
    else setSelectedIncidents(update)
  }

  function toggleRecord(id: number, checked: boolean) {
    const update = (current: number[]) => checked ? [...new Set([...current, id])] : current.filter((item) => item !== id)
    if (reportType === 'alerts') setSelectedAlerts(update)
    else setSelectedIncidents(update)
  }

  return <>
    <div className="page-intro"><div><p className="eyebrow">REPORTING</p><h2>Security Reports</h2><p className="muted">Build analyst-ready reports from stored alerts and incident investigation data.</p></div><button className="button button-secondary" onClick={() => void load()} disabled={loading}>↻ Refresh data</button></div>
    {error && <StateMessage error={error} onRetry={() => void load()} />}
    <Panel title="Configure report" subtitle={loading ? 'Loading data from the backend…' : `${alerts.length} alerts and ${incidents.length} incidents available from the backend`}>
      <div className="report-type-switch" role="group" aria-label="Report type">
        {(['alerts', 'incidents'] as const).map((type) => <button key={type} className={`report-type-option ${reportType === type ? 'report-type-active' : ''}`} aria-pressed={reportType === type} onClick={() => setReportType(type)}><span>{type === 'alerts' ? '◈' : '◎'}</span><strong>{type === 'alerts' ? 'Alert Report' : 'Incident Report'}</strong><small>{type === 'alerts' ? 'Detections, statuses and evidence' : 'Cases, timeline and investigation records'}</small></button>)}
      </div>
      <div className="report-controls">
        <label>From<input type="date" value={dateFrom} onChange={(event) => setDateFrom(event.target.value)} /></label>
        <label>To<input type="date" value={dateTo} onChange={(event) => setDateTo(event.target.value)} /></label>
        <label>Severity<select value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="">All severities</option>{['critical', 'high', 'medium', 'low'].map((item) => <option key={item} value={item}>{item}</option>)}</select></label>
        <label>Status<select value={status} onChange={(event) => setStatus(event.target.value)}><option value="">All statuses</option>{['open', 'investigating', 'resolved', 'false_positive'].map((item) => <option key={item} value={item}>{item.replaceAll('_', ' ')}</option>)}</select></label>
        {reportType === 'alerts' && <label>Detection type<select value={alertType} onChange={(event) => setAlertType(event.target.value)}><option value="">All types</option>{alertTypes.map((item) => <option key={item} value={item}>{item}</option>)}</select></label>}
        <label>Include<select value={selectedOnly ? 'selected' : 'matching'} onChange={(event) => setSelectedOnly(event.target.value === 'selected')}><option value="matching">All matching records</option><option value="selected">Selected records only</option></select></label>
      </div>
      <div className="report-selection-heading"><div><strong>{reportType === 'alerts' ? 'Alerts' : 'Incidents'} to include</strong><small>{selectedOnly ? `${currentSelection.length} selected` : 'Select individual rows or include all matching records'}</small></div><button type="button" className="text-button" onClick={() => toggleVisible(!allVisibleSelected)} disabled={loading || visibleIds.length === 0}>{allVisibleSelected ? 'Clear visible selection' : 'Select visible'}</button></div>
      <div className="table-scroll report-record-list"><table><thead><tr><th><input type="checkbox" aria-label="Select all visible records" checked={allVisibleSelected} onChange={(event) => toggleVisible(event.target.checked)} disabled={visibleIds.length === 0} /></th><th>{reportType === 'alerts' ? 'Detection' : 'Incident'}</th><th>Severity</th><th>Status</th><th>{reportType === 'alerts' ? 'Source → destination' : 'Updated'}</th><th>Timestamp</th></tr></thead><tbody>
        {reportType === 'alerts' ? visibleAlerts.map((alert) => <tr key={alert.id}><td><input type="checkbox" aria-label={`Select alert ${alert.id}`} checked={selectedAlerts.includes(alert.id)} onChange={(event) => toggleRecord(alert.id, event.target.checked)} /></td><td><strong>{alert.rule_name}</strong><small className="cell-sub">ALT-{alert.id} · {alert.alert_type}</small></td><td><Badge value={alert.severity} /></td><td><Badge value={alert.status} /></td><td className="mono">{alert.src_ip} → {alert.dst_ip}</td><td>{formatTime(alert.timestamp)}</td></tr>) : visibleIncidents.map((incident) => <tr key={incident.id}><td><input type="checkbox" aria-label={`Select incident ${incident.id}`} checked={selectedIncidents.includes(incident.id)} onChange={(event) => toggleRecord(incident.id, event.target.checked)} /></td><td><strong>{incident.title}</strong><small className="cell-sub">INC-{incident.id}</small></td><td><Badge value={incident.severity} /></td><td><Badge value={incident.status} /></td><td>{formatTime(incident.updated_at)}</td><td>{formatTime(incident.created_at)}</td></tr>)}
        {!loading && visibleIds.length === 0 && <tr><td colSpan={6} className="report-empty-cell">No records match these filters.</td></tr>}
      </tbody></table></div>
      <div className="report-generate-row"><span>{visibleIds.length} matching {reportType} · reports include data available when generated</span><button className="button button-primary" onClick={() => void generate()} disabled={loading || generating}>{generating ? 'Generating…' : 'Generate report'}</button></div>
    </Panel>

    {preview && <Panel title={`${preview.title} preview`} subtitle={`${preview.summary} · Generated ${formatTime(preview.generated_at)}`} action={<div className="report-export-actions"><button className="button button-secondary" onClick={() => void download('pdf')} disabled={downloading !== null}>{downloading === 'pdf' ? 'Preparing PDF…' : 'Export PDF'}</button><button className="button button-primary" onClick={() => void download('docx')} disabled={downloading !== null}>{downloading === 'docx' ? 'Preparing Word…' : 'Export Word'}</button></div>}>
      {downloadError && <div className="report-download-error">{downloadError}</div>}
      <div className="report-preview-summary"><div><small>REPORT SUMMARY</small><strong>{preview.record_count} {preview.report_type}</strong><span>{preview.summary}</span></div>{preview.report_type === 'alerts' && <><div><small>SEVERITY BREAKDOWN</small><div className="report-breakdown">{Object.entries(preview.severity_breakdown || {}).map(([key, count]) => <span key={key}><Badge value={key} /> <strong>{count}</strong></span>)}</div></div><div><small>DETECTION TYPES</small><div className="report-breakdown">{Object.entries(preview.alert_types || {}).map(([key, count]) => <span key={key}>{key} <strong>{count}</strong></span>)}</div></div></>}</div>
      {preview.report_type === 'alerts' ? <div className="report-preview-list">{(preview.alerts || []).map((alert) => <article className="report-alert" key={alert.id}><div className="report-alert-heading"><div><strong>ALT-{alert.id} · {alert.rule_name}</strong><small>{formatTime(alert.timestamp)} · {alert.source_ip} → {alert.destination_ip}</small></div><div><Badge value={alert.severity} /> <Badge value={alert.status} /></div></div><p>{alert.description || 'No description recorded.'}</p><details><summary>Recorded evidence</summary><Evidence value={alert.evidence} /></details></article>)}{!preview.record_count && <div className="empty-inline">No alerts matched the report selection.</div>}</div> : <div className="report-preview-list">{(preview.incidents || []).map((incident) => <IncidentReportPreview key={incident.id} incident={incident} />)}{!preview.record_count && <div className="empty-inline">No incidents matched the report selection.</div>}</div>}
    </Panel>}

    <Panel title="Recent reports" subtitle="Recently generated report previews on this device">
      {recent.length ? <div className="table-scroll"><table><thead><tr><th>Report</th><th>Records</th><th>Generated</th><th>Available</th></tr></thead><tbody>{recent.map((item, index) => <tr key={`${item.generated_at}-${index}`}><td><strong>{item.report_type === 'alerts' ? 'Alert Report' : 'Incident Report'}</strong></td><td>{item.record_count}</td><td>{formatTime(item.generated_at)}</td><td><span className="report-preview-state">Preview · export above</span></td></tr>)}</tbody></table></div> : <div className="empty-inline">Generated report previews will appear here.</div>}
    </Panel>
  </>
}

function IncidentReportPreview({ incident }: { incident: ReportIncidentRecord }) {
  return <article className="report-incident">
    <div className="report-incident-heading"><div><strong>INC-{incident.id} · {incident.title}</strong><p>{incident.summary || 'No summary recorded.'}</p></div><div><Badge value={incident.severity} /> <Badge value={incident.status} /></div></div>
    <div className="report-incident-meta"><span>Created <strong>{formatTime(incident.created_at)}</strong></span><span>Updated <strong>{formatTime(incident.updated_at)}</strong></span><span>{incident.alerts.length} associated alerts</span></div>
    <h3>Chronological alert timeline</h3>
    {incident.timeline.length ? <div className="table-scroll"><table><thead><tr><th>Timestamp</th><th>Rule / type</th><th>Severity</th><th>Source</th><th>Destination</th></tr></thead><tbody>{incident.timeline.map((item, index) => <tr key={`${item.timestamp}-${index}`}><td>{formatTime(item.timestamp)}</td><td><strong>{item.rule_name}</strong><small className="cell-sub">{item.type}</small></td><td><Badge value={item.severity} /></td><td className="mono">{item.source_ip}</td><td className="mono">{item.destination_ip}</td></tr>)}</tbody></table></div> : <p className="muted report-no-data">No associated alerts.</p>}
    <h3>Related telemetry</h3>
    {incident.related_telemetry.length ? <div className="table-scroll"><table><thead><tr><th>Timestamp</th><th>Event</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Details</th></tr></thead><tbody>{incident.related_telemetry.map((event) => <tr key={`${event.event_type}-${event.id}`}><td>{formatTime(event.timestamp)}</td><td>{event.event_type}{event.is_simulated ? <span className="simulation-tag">SIM</span> : null}</td><td className="mono">{event.source_ip}{event.source_port ? `:${event.source_port}` : ''}</td><td className="mono">{event.destination_ip}{event.destination_port ? `:${event.destination_port}` : ''}</td><td>{event.protocol}</td><td className="truncate">{Object.entries(event.details).map(([key, value]) => `${key}: ${String(value)}`).join(' · ') || '—'}</td></tr>)}</tbody></table></div> : <p className="muted report-no-data">No related telemetry was found for the investigation window.</p>}
    <div className="report-detail-columns"><section><h3>Indicators of compromise</h3>{[
      ['IP addresses', incident.iocs.ip_addresses], ['Domains', incident.iocs.domains], ['URLs', incident.iocs.urls], ['Destination ports', incident.iocs.destination_ports],
    ].map(([label, values]) => <div className="report-ioc-row" key={String(label)}><strong>{String(label)}</strong><span>{(values as (string | number)[]).join(', ') || 'None recorded'}</span></div>)}</section><section><h3>MITRE ATT&amp;CK</h3>{incident.mitre_techniques.length ? incident.mitre_techniques.map((technique) => <div className="report-plain-item" key={technique.technique_id}><strong>{technique.technique_id} · {technique.name}</strong><small>{technique.tactic} · {technique.source_detection_type}</small></div>) : <p className="muted">No techniques associated.</p>}</section></div>
    <div className="report-detail-columns"><section><h3>Investigation notes</h3>{incident.notes.length ? incident.notes.map((note) => <div className="report-plain-item" key={note.id}><span>{note.content}</span><small>{formatTime(note.created_at)}</small></div>) : <p className="muted">No analyst notes recorded.</p>}</section><section><h3>Investigation actions</h3>{incident.actions.length ? incident.actions.map((action) => <div className="report-plain-item" key={action.id}><strong>{action.action_type.replaceAll('_', ' ')}</strong><span>{action.comment || 'No comment'}</span><small>{formatTime(action.created_at)}</small></div>) : <p className="muted">No investigation actions recorded.</p>}</section></div>
    <details className="report-associated-alerts"><summary>Associated alerts and recorded evidence</summary>{incident.alerts.map((alert) => <div className="report-alert" key={alert.id}><div className="report-alert-heading"><div><strong>ALT-{alert.id} · {alert.rule_name}</strong><small>{formatTime(alert.timestamp)} · {alert.source_ip} → {alert.destination_ip}</small></div><div><Badge value={alert.severity} /> <Badge value={alert.status} /></div></div><p>{alert.description || 'No description recorded.'}</p><Evidence value={alert.evidence} /></div>)}</details>
  </article>
}

function SettingsPage({ theme, onThemeChange }: { theme: Theme; onThemeChange: (theme: Theme) => void }) {
  return <>
    <div className="page-intro"><div><p className="eyebrow">PREFERENCES</p><h2>Settings</h2><p className="muted">Adjust the appearance of this analyst workspace.</p></div></div>
    <Panel title="Appearance" subtitle="Choose the theme for this browser">
      <div className="appearance-setting"><div><strong>Theme</strong><small>The selection is saved on this device.</small></div>
        <div className="theme-options" role="group" aria-label="Appearance theme">
          {(['dark', 'light'] as const).map((choice) => <button key={choice} className={`theme-option ${theme === choice ? 'theme-option-selected' : ''}`} aria-pressed={theme === choice} onClick={() => onThemeChange(choice)}><span className={`theme-preview theme-preview-${choice}`} /><span>{choice === 'dark' ? 'Dark' : 'Light'}</span></button>)}
        </div>
      </div>
    </Panel>
  </>
}

function PlaceholderPage({ title }: { title: string }) {
  return <div className="placeholder-page"><div className="placeholder-icon">⌁</div><p className="eyebrow">NOT AVAILABLE</p><h2>{title}</h2><p>This workspace is reserved for {title.toLowerCase()} data. The current backend does not expose a supporting API yet.</p><span className="placeholder-tag">Backend integration pending</span></div>
}

function App() {
  const [page, setPage] = useState<Page>('Dashboard')
  const [theme, setTheme] = useState<Theme>(() => {
    const savedTheme = window.localStorage.getItem('threat-hunter-theme')
    if (savedTheme === 'dark' || savedTheme === 'light') return savedTheme
    return window.matchMedia?.('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
  })
  const [investigateIncidentId, setInvestigateIncidentId] = useState<number | null>(null)
  const [health, setHealth] = useState<'healthy' | 'unhealthy' | 'loading'>('loading')
  const [mobileNavOpen, setMobileNavOpen] = useState(false)
  const [healthError, setHealthError] = useState('')
  const refreshHealth = useCallback(async () => {
    setHealth('loading'); setHealthError('')
    try { const result = await api.health(); setHealth(result.status === 'healthy' ? 'healthy' : 'unhealthy') }
    catch (cause) { setHealth('unhealthy'); setHealthError(cause instanceof Error ? cause.message : 'API unavailable') }
  }, [])
  useEffect(() => { void refreshHealth() }, [refreshHealth])
  useEffect(() => {
    document.documentElement.dataset.theme = theme
    window.localStorage.setItem('threat-hunter-theme', theme)
  }, [theme])
  function navigate(next: Page) { setPage(next); setMobileNavOpen(false) }
  return <div className="app-shell">
    <aside className={`sidebar ${mobileNavOpen ? 'sidebar-open' : ''}`}>
      <div className="brand"><div className="brand-mark"><span>TH</span><i /></div><div><strong>THREAT<span>HUNTER</span></strong><small>NETWORK DEFENSE</small></div></div>
      <div className="sensor-card"><span className={`sensor-indicator ${health}`} /><div><strong>Network sensor</strong><small>{health === 'loading' ? 'Checking connection' : health === 'healthy' ? 'API connected' : 'API unavailable'}</small></div><button className="mini-refresh" aria-label="Refresh API health" onClick={() => void refreshHealth()}>↻</button></div>
      {['WORKSPACE', 'RESPONSE', 'INTELLIGENCE', 'SYSTEM'].map((section) => <div className="nav-section" key={section}><p>{section}</p>{NAV.filter((item) => item.section === section).map((item) => <button key={item.name} className={`nav-item ${page === item.name ? 'nav-active' : ''}`} onClick={() => navigate(item.name)}><span className="nav-icon">{item.icon}</span><span>{item.name}</span></button>)}</div>)}
      <div className="sidebar-footer"><div className="footer-avatar">SOC</div><div><strong>Analyst workspace</strong><small>Local deployment</small></div></div>
    </aside>
    {mobileNavOpen && <button className="mobile-scrim" aria-label="Close navigation" onClick={() => setMobileNavOpen(false)} />}
    <main className="main-area"><header className="topbar"><button className="mobile-menu" onClick={() => setMobileNavOpen(!mobileNavOpen)} aria-label="Toggle navigation">☰</button><div className="breadcrumb"><span>Network Threat Hunter</span><b>/</b><strong>{page}</strong></div><div className="topbar-right"><span className="utc-label">SOC CONSOLE</span><button className="top-health" onClick={() => void refreshHealth()}><i className={`sensor-indicator ${health}`} />{health === 'loading' ? 'Connecting' : health === 'healthy' ? 'System operational' : 'Backend offline'}</button></div></header>
      {healthError && <div className="global-api-error"><span>{healthError}</span><button onClick={() => void refreshHealth()}>Retry</button></div>}
      <div className="page-content">{page === 'Dashboard' && <DashboardPage />}{page === 'Alerts' && <AlertsPage />}{page === 'Threat Hunting' && <HuntPage />}{page === 'Attack Lab' && <AttackLabPage onInvestigate={(id) => { setInvestigateIncidentId(id); navigate('Investigation') }} />}{page === 'Incidents' && <IncidentsPage />}{page === 'Investigation' && <InvestigationPage incidentId={investigateIncidentId} />}{page === 'MITRE ATT&CK' && <MitrePage />}{page === 'Reports' && <ReportsPage />}{page === 'Settings' && <SettingsPage theme={theme} onThemeChange={setTheme} />}{page === 'Hosts' && <PlaceholderPage title={page} />}</div>
      <footer className="app-footer"><span>NETWORK THREAT HUNTER <i>·</i> SOC WORKSPACE</span><span>DATA FROM CONFIGURED BACKEND APIS</span></footer>
    </main>
  </div>
}

export default App
