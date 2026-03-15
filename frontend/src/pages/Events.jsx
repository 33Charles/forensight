import { useEffect, useState, useCallback, useRef } from 'react'
import {
  ChevronDown, ChevronUp, RefreshCw, Filter, Download,
  X, Search, CheckSquare, Square, Clock, Zap
} from 'lucide-react'
import api from '../utils/api'
import { useSocket } from '../hooks/useSocket'
import {
  SeverityBadge, StatusBadge, EventTypeBadge,
  PageHeader, EmptyState, Select
} from '../components/ui'
import { SkeletonTable } from '../components/ui/Skeleton'
import { formatTime } from '../utils/helpers'
import { exportToCSV } from '../utils/export'

const STATUS_OPTIONS = [
  { value: '',              label: 'All statuses'  },
  { value: 'open',          label: 'Open'          },
  { value: 'investigating', label: 'Investigating' },
  { value: 'resolved',      label: 'Resolved'      },
]
const SEVERITY_OPTIONS = [
  { value: '',         label: 'All severities' },
  { value: 'critical', label: 'Critical'       },
  { value: 'high',     label: 'High'           },
  { value: 'medium',   label: 'Medium'         },
  { value: 'low',      label: 'Low'            },
]
const TYPE_OPTIONS = [
  { value: '',                         label: 'All types'             },
  { value: 'brute_force',              label: 'Brute Force'          },
  { value: 'brute_force_success',      label: 'Brute Force Success'  },
  { value: 'root_login_attempt',       label: 'Root Login'           },
  { value: 'privilege_escalation',     label: 'Privilege Escalation' },
  { value: 'unauthorized_sudo',        label: 'Unauthorized Sudo'    },
  { value: 'sudo_brute_force',         label: 'Sudo Brute Force'     },
  { value: 'sensitive_file_access',    label: 'Sensitive File'       },
  { value: 'unauthorized_file_access', label: 'Unauthorized File'    },
  { value: 'port_scan',                label: 'Port Scan'            },
  { value: 'reverse_shell',            label: 'Reverse Shell'        },
  { value: 'c2_connection',            label: 'C2 Beaconing'         },
  { value: 'ssh_login_success',        label: 'SSH Login'            },
]
const SOURCE_OPTIONS = [
  { value: '',           label: 'All sources' },
  { value: 'live',       label: 'Live'        },
  { value: 'historical', label: 'Historical'  },
]
const TIME_OPTIONS = [
  { value: '',      label: 'All time'       },
  { value: '1',     label: 'Last 1 hour'   },
  { value: '6',     label: 'Last 6 hours'  },
  { value: '24',    label: 'Last 24 hours' },
  { value: '72',    label: 'Last 3 days'   },
  { value: '168',   label: 'Last 7 days'   },
  { value: 'custom',label: 'Custom range'  },
]

const SEVERITY_COLORS = {
  critical: 'text-critical', high: 'text-high',
  medium: 'text-medium', low: 'text-low',
}

function EventRow({ event, selected, onSelect, onStatusChange, isNew }) {
  const [expanded, setExpanded] = useState(false)
  const [updating, setUpdating] = useState(false)

  const handleStatus = async (e, status) => {
    e.stopPropagation()
    setUpdating(true)
    try {
      const { data } = await api.patch(`/events/${event.id}/status`, { status })
      onStatusChange(data)
    } finally {
      setUpdating(false)
    }
  }

  return (
    <>
      <tr
        className={`border-b border-border/50 cursor-pointer transition-all duration-300
                    ${isNew ? 'bg-accent/10 animate-fade-in' : 'hover:bg-muted/30'}
                    ${selected ? 'bg-accent/5 border-l-2 border-l-accent' : ''}`}
        onClick={() => setExpanded(v => !v)}
      >
        {/* Checkbox */}
        <td className="px-3 py-3" onClick={e => { e.stopPropagation(); onSelect(event.id) }}>
          <div className={`text-subtle hover:text-accent transition-colors
                           ${selected ? 'text-accent' : ''}`}>
            {selected ? <CheckSquare size={14} /> : <Square size={14} />}
          </div>
        </td>
        <td className="px-4 py-3"><SeverityBadge severity={event.severity} /></td>
        <td className="px-4 py-3"><EventTypeBadge type={event.event_type} /></td>
        <td className="px-4 py-3 text-xs font-mono text-dim">{event.source_ip ?? '—'}</td>
        <td className="px-4 py-3 text-xs font-mono text-dim">{event.target_host ?? '—'}</td>
        <td className="px-4 py-3 text-xs font-mono text-dim">{event.username ?? '—'}</td>
        <td className="px-4 py-3"><StatusBadge status={event.status} /></td>
        <td className="px-4 py-3">
          <span className={`badge border text-xs font-mono
            ${event.source === 'live'
              ? 'text-low bg-low/10 border-low/20'
              : 'text-accent bg-accent/10 border-accent/20'
            }`}>
            {event.source}
          </span>
        </td>
        <td className="px-4 py-3 text-xs font-mono text-subtle whitespace-nowrap">
          {isNew && (
            <span className="inline-flex items-center gap-1 text-accent mr-1">
              <Zap size={10} />
            </span>
          )}
          {formatTime(event.timestamp)}
        </td>
        <td className="px-4 py-3 text-dim">
          {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
        </td>
      </tr>

      {expanded && (
        <tr className="bg-surface/50 border-b border-border animate-slide-in">
          <td colSpan={10} className="px-4 py-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <p className="text-xs text-subtle font-mono uppercase tracking-widest mb-1.5">
                  Description
                </p>
                <p className="text-sm text-text">{event.description}</p>
              </div>

              {(event.mitre_technique || event.mitre_tactic) && (
                <div>
                  <p className="text-xs text-subtle font-mono uppercase tracking-widest mb-1.5">
                    MITRE ATT&CK
                  </p>
                  <div className="flex gap-2 flex-wrap">
                    {event.mitre_technique && (
                      <span className="badge bg-info/10 text-info border border-info/20">
                        {event.mitre_technique}
                      </span>
                    )}
                    {event.mitre_tactic && (
                      <span className="badge bg-accent/10 text-accent border border-accent/20">
                        {event.mitre_tactic}
                      </span>
                    )}
                  </div>
                </div>
              )}

              {/* Timestamps + Audit trail */}
              <div>
                <p className="text-xs text-subtle font-mono uppercase tracking-widest mb-1.5">
                  Audit Trail
                </p>
                <div className="space-y-1.5">
                  <p className="text-xs font-mono text-dim flex items-center gap-1.5">
                    <Clock size={11} className="text-subtle" />
                    Detected:
                    <span className="text-text">{formatTime(event.timestamp)}</span>
                  </p>
                  {event.investigated_by && (
                    <p className="text-xs font-mono text-dim flex items-center gap-1.5">
                      <Clock size={11} className="text-medium" />
                      Investigating:
                      <span className="text-medium font-medium">{event.investigated_by}</span>
                    </p>
                  )}
                  {event.resolved_at && (
                    <p className="text-xs font-mono text-dim flex items-center gap-1.5">
                      <Clock size={11} className="text-low" />
                      Resolved:
                      <span className="text-low">{formatTime(event.resolved_at)}</span>
                      {event.resolved_by && (
                        <span className="text-low font-medium">by {event.resolved_by}</span>
                      )}
                    </p>
                  )}
                </div>
              </div>

              <div className="md:col-span-2">
                <p className="text-xs text-subtle font-mono uppercase tracking-widest mb-1.5">
                  Update Status
                </p>
                <div className="flex gap-2">
                  {['open','investigating','resolved'].map(s => (
                    <button
                      key={s}
                      disabled={updating || event.status === s}
                      onClick={(e) => handleStatus(e, s)}
                      className={`text-xs px-3 py-1.5 rounded-lg border transition-all capitalize
                        ${event.status === s
                          ? 'bg-accent/20 text-accent border-accent/30 font-medium'
                          : 'text-dim border-border hover:border-accent/30 hover:text-text'
                        } disabled:opacity-40`}
                    >
                      {s}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

export default function Events() {
  const [events,      setEvents]      = useState([])
  const [hosts,       setHosts]       = useState([])
  const [loading,     setLoading]     = useState(true)
  const [totalCount,  setTotalCount]  = useState(0)
  const [severity,    setSeverity]    = useState('')
  const [status,      setStatus]      = useState('open')
  const [showResolved, setShowResolved] = useState(false)
  const [type,        setType]        = useState('')
  const [host,        setHost]        = useState('')
  const [source,      setSource]      = useState('')
  const [timeRange,   setTimeRange]   = useState('')
  const [dateFrom,    setDateFrom]    = useState('')
  const [dateTo,      setDateTo]      = useState('')
  const [search,      setSearch]      = useState('')
  const [selected,    setSelected]    = useState(new Set())
  const [bulkStatus,  setBulkStatus]  = useState('')
  const [bulkLoading, setBulkLoading] = useState(false)
  const [newEventIds, setNewEventIds] = useState(new Set())
  const [resolvedCount, setResolvedCount] = useState(0)
  const [autoRefresh, setAutoRefresh] = useState(false)
  const autoRefreshRef                = useRef(null)

  useEffect(() => {
    api.get('/hosts').then(r =>
      setHosts([{ value: '', label: 'All hosts' },
                ...r.data.map(h => ({ value: h, label: h }))])
    )
  }, [])

  const fetchEvents = useCallback(async () => {
    setLoading(true)
    try {
      const params = { limit: 500 }
      if (severity) params.severity    = severity
      if (status)   params.status      = status
      if (type)     params.event_type  = type
      if (host)     params.target_host = host
      if (source)   params.source      = source
      const [{ data }, total, resolved] = await Promise.all([
        api.get('/events', { params }),
        api.get('/stats'),
        api.get('/events', { params: { status: 'resolved', limit: 500 } }),
      ])
      setEvents(data)
      setTotalCount(total.data.total_events)
      setResolvedCount(resolved.data.length)
      setSelected(new Set())
    } finally {
      setLoading(false)
    }
  }, [severity, status, type, host, source])

  useEffect(() => { fetchEvents() }, [fetchEvents])

  // Auto-refresh
  useEffect(() => {
    if (autoRefresh) {
      autoRefreshRef.current = setInterval(fetchEvents, 30000)
    } else {
      clearInterval(autoRefreshRef.current)
    }
    return () => clearInterval(autoRefreshRef.current)
  }, [autoRefresh, fetchEvents])

  // Live events — prepend and highlight
  useSocket((event) => {
    setEvents(prev => [event, ...prev])
    setNewEventIds(prev => new Set([...prev, event.id ?? `live-${Date.now()}`]))
    // Remove highlight after 8s
    setTimeout(() => {
      setNewEventIds(prev => {
        const next = new Set(prev)
        next.delete(event.id ?? `live-${Date.now()}`)
        return next
      })
    }, 8000)
  }, null)

  const handleStatusChange = (updated) => {
    setEvents(prev => prev.map(e => e.id === updated.id ? updated : e))
  }

  // Selection
  const toggleSelect = (id) => {
    setSelected(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  const toggleSelectAll = () => {
    if (selected.size === filtered.length) {
      setSelected(new Set())
    } else {
      setSelected(new Set(filtered.map(e => e.id)))
    }
  }

  // Bulk status update
  const handleBulkUpdate = async () => {
    if (!bulkStatus || selected.size === 0) return
    setBulkLoading(true)
    try {
      await Promise.all(
        [...selected].map(id => api.patch(`/events/${id}/status`, { status: bulkStatus }))
      )
      setEvents(prev => prev.map(e =>
        selected.has(e.id) ? { ...e, status: bulkStatus } : e
      ))
      setSelected(new Set())
      setBulkStatus('')
    } finally {
      setBulkLoading(false)
    }
  }

  // Client-side filtering (time range + search)
  const filtered = events.filter(e => {
    if (search) {
      const q = search.toLowerCase()
      const match =
        e.description?.toLowerCase().includes(q) ||
        e.source_ip?.toLowerCase().includes(q)   ||
        e.username?.toLowerCase().includes(q)    ||
        e.target_host?.toLowerCase().includes(q) ||
        e.event_type?.toLowerCase().includes(q)
      if (!match) return false
    }

    const ts = new Date(e.timestamp + 'Z').getTime()

    if (timeRange && timeRange !== 'custom') {
      const cutoff = Date.now() - parseInt(timeRange) * 60 * 60 * 1000
      if (ts < cutoff) return false
    }

    if (timeRange === 'custom') {
      if (dateFrom && ts < new Date(dateFrom).getTime()) return false
      if (dateTo   && ts > new Date(dateTo).getTime())   return false
    }

    return true
  })

  // Severity counts for filtered view
  const severityCounts = filtered.reduce((acc, e) => {
    acc[e.severity] = (acc[e.severity] ?? 0) + 1
    return acc
  }, {})

  const handleExport = () => {
    exportToCSV(
      filtered.map(e => ({
        timestamp:       e.timestamp,
        severity:        e.severity,
        event_type:      e.event_type,
        source_ip:       e.source_ip ?? '',
        target_host:     e.target_host ?? '',
        username:        e.username ?? '',
        description:     e.description,
        status:          e.status,
        source:          e.source,
        mitre_technique: e.mitre_technique ?? '',
        mitre_tactic:    e.mitre_tactic ?? '',
      })),
      `forensight-events-${new Date().toISOString().slice(0,10)}.csv`
    )
  }

  const toggleShowResolved = () => {
    if (showResolved) {
      setStatus('open')
      setShowResolved(false)
    } else {
      setStatus('')
      setShowResolved(true)
    }
  }

  const clearFilters = () => {
    setSeverity(''); setStatus('open'); setType('')
    setHost(''); setSource(''); setTimeRange('')
    setDateFrom(''); setDateTo(''); setSearch('')
    setShowResolved(false)
  }

  const hasFilters = severity || status || type || host ||
                     source || timeRange || search

  // Active filter chips
  const chips = [
    severity  && { label: `Severity: ${severity}`,   clear: () => setSeverity('')  },
    status    && { label: `Status: ${status}`,        clear: () => setStatus('')    },
    type      && { label: `Type: ${type.replace(/_/g,' ')}`, clear: () => setType('') },
    host      && { label: `Host: ${host}`,            clear: () => setHost('')      },
    source    && { label: `Source: ${source}`,        clear: () => setSource('')    },
    timeRange && { label: timeRange === 'custom'
                    ? `${dateFrom || '?'} → ${dateTo || '?'}`
                    : `Last ${timeRange}h`,            clear: () => { setTimeRange(''); setDateFrom(''); setDateTo('') }},
    search    && { label: `"${search}"`,              clear: () => setSearch('')    },
  ].filter(Boolean)

  return (
    <div className="animate-fade-in">
      <PageHeader title="Events" subtitle={`Showing ${filtered.length} of ${totalCount} total events`}>
        <button
          onClick={() => setAutoRefresh(v => !v)}
          className={`flex items-center gap-1.5 text-xs px-3 py-2 rounded-lg border
                      transition-all font-mono
                      ${autoRefresh
                        ? 'bg-low/10 text-low border-low/30'
                        : 'text-dim border-border hover:text-text'
                      }`}
        >
          <RefreshCw size={12} className={autoRefresh ? 'animate-spin' : ''} style={autoRefresh ? {animationDuration:'3s'} : {}} />
          {autoRefresh ? 'Auto' : 'Auto off'}
        </button>
        <button
          onClick={handleExport}
          disabled={filtered.length === 0}
          className="btn-ghost flex items-center gap-1.5 disabled:opacity-40"
        >
          <Download size={13} />
          Export CSV
        </button>
        <button onClick={fetchEvents} className="btn-ghost flex items-center gap-1.5">
          <RefreshCw size={13} />
          Refresh
        </button>
      </PageHeader>

      {/* Severity count badges */}
      {filtered.length > 0 && (
        <div className="flex gap-2 mb-4 flex-wrap">
          {['critical','high','medium','low'].map(s =>
            severityCounts[s] ? (
              <span
                key={s}
                onClick={() => setSeverity(s)}
                className={`badge border cursor-pointer hover:opacity-80 transition-opacity
                            ${s === 'critical' ? 'text-critical bg-critical/10 border-critical/20' :
                              s === 'high'     ? 'text-high bg-high/10 border-high/20' :
                              s === 'medium'   ? 'text-medium bg-medium/10 border-medium/20' :
                                                 'text-low bg-low/10 border-low/20'}`}
              >
                {severityCounts[s]} {s}
              </span>
            ) : null
          )}
        </div>
      )}

      {/* Resolved toggle */}
      <div className="flex items-center gap-3 mb-4">
        <button
          onClick={toggleShowResolved}
          className={`text-xs font-mono px-3 py-1.5 rounded-lg border transition-all
                      flex items-center gap-1.5
                      ${showResolved
                        ? 'bg-low/10 text-low border-low/20'
                        : 'text-subtle border-border hover:text-dim hover:border-subtle'
                      }`}
        >
          {showResolved ? '✓ Showing resolved' : `Show resolved`}
          {!showResolved && resolvedCount > 0 && (
            <span className="bg-muted text-text px-1.5 py-0.5 rounded font-mono text-[10px] ml-0.5 font-medium">
              {resolvedCount}
            </span>
          )}
        </button>
      </div>

      {/* Filters */}
      <div className="card mb-4 p-4">
        <div className="flex items-center gap-2 mb-3">
          <Filter size={13} className="text-subtle" />
          <span className="text-xs font-mono text-subtle uppercase tracking-widest">Filters</span>
          {hasFilters && (
            <button
              onClick={clearFilters}
              className="ml-auto text-xs text-dim hover:text-critical flex items-center gap-1 transition-colors"
            >
              <X size={11} />
              Clear all
            </button>
          )}
        </div>

        {/* Dropdowns */}
        <div className="flex gap-3 flex-wrap mb-3">
          <Select value={severity}  onChange={setSeverity}  options={SEVERITY_OPTIONS} className="w-36" />
          <Select value={status} onChange={v => {
            setStatus(v)
            setShowResolved(v === '' || v === 'resolved')
          }} options={STATUS_OPTIONS} className="w-36" />
          <Select value={type}      onChange={setType}      options={TYPE_OPTIONS}     className="w-48" />
          <Select value={host}      onChange={setHost}      options={hosts}            className="w-40" />
          <Select value={source}    onChange={setSource}    options={SOURCE_OPTIONS}   className="w-36" />
          <Select value={timeRange} onChange={setTimeRange} options={TIME_OPTIONS}     className="w-40" />
        </div>

        {/* Custom date range */}
        {timeRange === 'custom' && (
          <div className="flex gap-3 flex-wrap mb-3 animate-slide-in">
            <div className="flex items-center gap-2">
              <label className="text-xs text-dim font-mono whitespace-nowrap">From</label>
              <input
                type="datetime-local"
                value={dateFrom}
                onChange={e => setDateFrom(e.target.value)}
                className="input w-52 text-xs"
              />
            </div>
            <div className="flex items-center gap-2">
              <label className="text-xs text-dim font-mono whitespace-nowrap">To</label>
              <input
                type="datetime-local"
                value={dateTo}
                onChange={e => setDateTo(e.target.value)}
                className="input w-52 text-xs"
              />
            </div>
          </div>
        )}

        {/* Search */}
        <div className="relative">
          <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-subtle" />
          <input
            className="input pl-8 pr-8"
            placeholder="Search description, IP, username, host, event type..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
          {search && (
            <button
              onClick={() => setSearch('')}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-subtle hover:text-dim"
            >
              <X size={12} />
            </button>
          )}
        </div>

        {/* Active filter chips */}
        {chips.length > 0 && (
          <div className="flex gap-2 flex-wrap mt-3">
            {chips.map((chip, i) => (
              <span
                key={i}
                className="flex items-center gap-1 text-xs font-mono px-2 py-1
                           bg-accent/10 text-accent border border-accent/20 rounded-lg"
              >
                {chip.label}
                <button onClick={chip.clear} className="hover:text-white ml-0.5">
                  <X size={10} />
                </button>
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Bulk actions bar */}
      {selected.size > 0 && (
        <div className="flex items-center gap-3 mb-4 px-4 py-3 bg-accent/10
                        border border-accent/20 rounded-xl animate-slide-in">
          <CheckSquare size={14} className="text-accent" />
          <span className="text-sm text-accent font-medium">
            {selected.size} event{selected.size !== 1 ? 's' : ''} selected
          </span>
          <div className="flex items-center gap-2 ml-auto">
            <span className="text-xs text-dim font-mono">Update status:</span>
            {['open','investigating','resolved'].map(s => (
              <button
                key={s}
                onClick={() => { setBulkStatus(s); }}
                className={`text-xs px-3 py-1.5 rounded-lg border transition-all capitalize
                  ${bulkStatus === s
                    ? 'bg-accent/20 text-accent border-accent/30 font-medium'
                    : 'text-dim border-border hover:border-accent/30 hover:text-text'
                  }`}
              >
                {s}
              </button>
            ))}
            <button
              onClick={handleBulkUpdate}
              disabled={!bulkStatus || bulkLoading}
              className="btn-primary text-xs disabled:opacity-40"
            >
              {bulkLoading ? 'Updating...' : 'Apply'}
            </button>
            <button
              onClick={() => { setSelected(new Set()); setBulkStatus('') }}
              className="text-subtle hover:text-dim"
            >
              <X size={14} />
            </button>
          </div>
        </div>
      )}

      {loading ? (
        <SkeletonTable rows={8} cols={10} />
      ) : filtered.length === 0 ? (
        <div className="card">
          <EmptyState icon={Filter} message="No events match your filters" />
        </div>
      ) : (
        <div className="card p-0 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-surface/60">
                  {/* Select all checkbox */}
                  <th className="px-3 py-3 w-8"
                      onClick={toggleSelectAll}>
                    <div className={`cursor-pointer transition-colors
                                     ${selected.size === filtered.length && filtered.length > 0
                                       ? 'text-accent' : 'text-subtle hover:text-dim'}`}>
                      {selected.size === filtered.length && filtered.length > 0
                        ? <CheckSquare size={14} />
                        : <Square size={14} />
                      }
                    </div>
                  </th>
                  {['Severity','Type','Source IP','Target','User','Status','Source','Time',''].map(h => (
                    <th key={h} className="px-4 py-3 text-left text-xs font-mono
                                           text-subtle uppercase tracking-widest font-medium">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filtered.map(e => (
                  <EventRow
                    key={e.id}
                    event={e}
                    selected={selected.has(e.id)}
                    onSelect={toggleSelect}
                    onStatusChange={handleStatusChange}
                    isNew={newEventIds.has(e.id)}
                  />
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
