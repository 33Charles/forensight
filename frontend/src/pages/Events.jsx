import { useEffect, useState, useCallback, useRef } from 'react'
import {
  ChevronDown, ChevronUp, RefreshCw, Filter, Download,
  X, Search, CheckSquare, Square, Clock, Zap,
  List, Layers, Plus, MessageSquare, ChevronsUpDown, ArrowUp, ArrowDown
} from 'lucide-react'
import api from '../utils/api'
import { useAuth } from '../context/AuthContext'
import { useSocket } from '../hooks/useSocket'
import {
  SeverityBadge, StatusBadge, EventTypeBadge,
  PageHeader, EmptyState, Select
} from '../components/ui'
import { SkeletonTable } from '../components/ui/Skeleton'
import { formatTime, severityColor } from '../utils/helpers'
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
  { value: '',       label: 'All time'       },
  { value: '1',      label: 'Last 1 hour'   },
  { value: '6',      label: 'Last 6 hours'  },
  { value: '24',     label: 'Last 24 hours' },
  { value: '72',     label: 'Last 3 days'   },
  { value: '168',    label: 'Last 7 days'   },
  { value: 'custom', label: 'Custom range'  },
]

// Available group-by fields
const GROUP_FIELDS = [
  { value: 'event_type',  label: 'Event Type'  },
  { value: 'source_ip',   label: 'Source IP'   },
  { value: 'username',    label: 'Username'    },
  { value: 'target_host', label: 'Target Host' },
  { value: 'severity',    label: 'Severity'    },
  { value: 'source',      label: 'Source'      },
]

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 }

// ── SortableHeader ───────────────────────────────────────────────────────────
function SortableHeader({ label, field, sortField, sortDir, onSort }) {
  const active = sortField === field
  return (
    <th
      className="px-4 py-3 text-left text-xs font-mono text-subtle uppercase
                 tracking-widest font-medium cursor-pointer hover:text-dim
                 select-none group"
      onClick={() => onSort(field)}
    >
      <span className="flex items-center gap-1">
        {label}
        <span className={`transition-colors ${active ? 'text-accent' : 'text-subtle/0 group-hover:text-subtle'}`}>
          {active
            ? sortDir === 'asc' ? <ArrowUp size={11} /> : <ArrowDown size={11} />
            : <ChevronsUpDown size={11} />
          }
        </span>
      </span>
    </th>
  )
}

// ── NotesEditor ──────────────────────────────────────────────────────────────
function NotesEditor({ event, onUpdate, currentUser }) {
  const [editing, setEditing] = useState(false)
  const [notes,   setNotes]   = useState(event.notes ?? '')
  const [saving,  setSaving]  = useState(false)
  const [error,   setError]   = useState('')
  const textRef               = useRef(null)

  // Determine if current user can edit notes
  const canEdit = (() => {
    if (event.status === 'open') return false
    if (event.status === 'investigating')
      return event.investigated_by === currentUser
    if (event.status === 'resolved')
      return event.resolved_by === currentUser
    return false
  })()

  // Who owns the notes
  const owner = event.status === 'investigating'
    ? event.investigated_by
    : event.resolved_by

  useEffect(() => {
    if (editing) textRef.current?.focus()
  }, [editing])

  const handleSave = async (e) => {
    e.stopPropagation()
    setSaving(true)
    setError('')
    try {
      const { data } = await api.patch(`/events/${event.id}/notes`, { notes })
      onUpdate(data)
      setEditing(false)
    } catch (err) {
      setError(err.response?.data?.error ?? 'Failed to save note')
    } finally {
      setSaving(false)
    }
  }

  const handleCancel = (e) => {
    e.stopPropagation()
    setNotes(event.notes ?? '')
    setEditing(false)
    setError('')
  }

  // open state — notes not available
  if (event.status === 'open') return null

  // Read-only view for non-owners
  if (!canEdit) {
    return (
      <div className="min-h-10 px-3 py-2.5 rounded-lg border border-border/50
                      bg-surface/40 text-xs">
        {event.notes
          ? <>
              <p className="text-text whitespace-pre-wrap">{event.notes}</p>
              {owner && (
                <p className="text-subtle font-mono mt-1.5 text-[10px]">
                  — {owner}
                </p>
              )}
            </>
          : <span className="text-subtle italic">No notes added yet</span>
        }
      </div>
    )
  }

  if (!editing) {
    return (
      <div
        onClick={e => { e.stopPropagation(); setEditing(true) }}
        className={`min-h-10 px-3 py-2.5 rounded-lg border text-xs cursor-text
                    transition-colors
                    ${event.notes
                      ? 'border-border bg-surface/60 text-text hover:border-accent/40'
                      : 'border-dashed border-border/60 bg-transparent text-subtle hover:border-accent/40 hover:text-dim'
                    }`}
      >
        {event.notes
          ? <span className="whitespace-pre-wrap">{event.notes}</span>
          : <span className="flex items-center gap-1.5">
              <MessageSquare size={11} />
              Click to add a note...
            </span>
        }
      </div>
    )
  }

  return (
    <div onClick={e => e.stopPropagation()} className="space-y-2">
      <textarea
        ref={textRef}
        value={notes}
        onChange={e => setNotes(e.target.value)}
        rows={3}
        placeholder="Add analyst notes, e.g. 'Confirmed false positive — dev machine'"
        className="input text-xs resize-none font-mono"
      />
      {error && (
        <p className="text-xs text-critical font-mono">{error}</p>
      )}
      <div className="flex gap-2">
        <button onClick={handleSave} disabled={saving}
          className="btn-primary text-xs px-3 py-1.5 disabled:opacity-40">
          {saving ? 'Saving...' : 'Save Note'}
        </button>
        <button onClick={handleCancel}
          className="text-xs text-dim border border-border hover:text-text
                     px-3 py-1.5 rounded-lg transition-colors">
          Cancel
        </button>
      </div>
    </div>
  )
}

// ── EventRow ──────────────────────────────────────────────────────────────────
function EventRow({ event, selected, onSelect, onStatusChange, isNew, compact, currentUser }) {
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
                    ${isNew ? 'bg-accent/10' : 'hover:bg-muted/30'}
                    ${selected ? 'bg-accent/5 border-l-2 border-l-accent' : ''}
                    ${compact ? 'text-xs' : ''}`}
        onClick={() => setExpanded(v => !v)}
      >
        <td className="px-3 py-2.5" onClick={e => { e.stopPropagation(); onSelect(event.id) }}>
          <div className={`text-subtle hover:text-accent transition-colors ${selected ? 'text-accent' : ''}`}>
            {selected ? <CheckSquare size={13} /> : <Square size={13} />}
          </div>
        </td>
        <td className="px-3 py-2.5"><SeverityBadge severity={event.severity} /></td>
        <td className="px-3 py-2.5"><EventTypeBadge type={event.event_type} /></td>
        <td className="px-3 py-2.5 font-mono text-dim">{event.source_ip ?? '—'}</td>
        <td className="px-3 py-2.5 font-mono text-dim">{event.target_host ?? '—'}</td>
        <td className="px-3 py-2.5 font-mono text-dim">{event.username ?? '—'}</td>
        <td className="px-3 py-2.5"><StatusBadge status={event.status} /></td>
        <td className="px-3 py-2.5">
          <span className={`badge border font-mono
            ${event.source === 'live'
              ? 'text-low bg-low/10 border-low/20'
              : 'text-accent bg-accent/10 border-accent/20'}`}>
            {event.source}
          </span>
        </td>
        <td className="px-3 py-2.5 font-mono text-subtle whitespace-nowrap">
          {isNew && <Zap size={10} className="inline text-accent mr-1" />}
          {formatTime(event.timestamp)}
        </td>
        <td className="px-3 py-2.5 text-dim">
          {expanded ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
        </td>
      </tr>

      {expanded && (
        <tr className="bg-surface/50 border-b border-border animate-slide-in">
          <td colSpan={10} className="px-4 py-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <p className="text-xs text-subtle font-mono uppercase tracking-widest mb-1.5">Description</p>
                <p className="text-sm text-text">{event.description}</p>
              </div>
              {(event.mitre_technique || event.mitre_tactic) && (
                <div>
                  <p className="text-xs text-subtle font-mono uppercase tracking-widest mb-1.5">MITRE ATT&CK</p>
                  <div className="flex gap-2 flex-wrap">
                    {event.mitre_technique && (
                      <span className="badge bg-info/10 text-info border border-info/20">{event.mitre_technique}</span>
                    )}
                    {event.mitre_tactic && (
                      <span className="badge bg-accent/10 text-accent border border-accent/20">{event.mitre_tactic}</span>
                    )}
                  </div>
                </div>
              )}
              <div>
                <p className="text-xs text-subtle font-mono uppercase tracking-widest mb-1.5">Audit Trail</p>
                <div className="space-y-1.5">
                  <p className="text-xs font-mono text-dim flex items-center gap-1.5">
                    <Clock size={11} className="text-subtle" />
                    Detected: <span className="text-text">{formatTime(event.timestamp)}</span>
                  </p>
                  {event.investigated_by && (
                    <p className="text-xs font-mono text-dim flex items-center gap-1.5">
                      <Clock size={11} className="text-medium" />
                      Investigating: <span className="text-medium font-medium">{event.investigated_by}</span>
                    </p>
                  )}
                  {event.resolved_at && (
                    <p className="text-xs font-mono text-dim flex items-center gap-1.5">
                      <Clock size={11} className="text-low" />
                      Resolved: <span className="text-low">{formatTime(event.resolved_at)}</span>
                      {event.resolved_by && <span className="text-low font-medium">by {event.resolved_by}</span>}
                    </p>
                  )}
                </div>
              </div>
              {/* Notes */}
              <div className="md:col-span-2">
                <p className="text-xs text-subtle font-mono uppercase tracking-widest mb-1.5 flex items-center gap-1.5">
                  <MessageSquare size={11} />
                  Analyst Notes
                </p>
                <NotesEditor event={event} onUpdate={onStatusChange} currentUser={currentUser} />
              </div>

              <div className="md:col-span-2">
                <p className="text-xs text-subtle font-mono uppercase tracking-widest mb-1.5">Update Status</p>
                {(() => {
                  // Determine if current user can change status
                  const isLocked =
                    (event.status === 'investigating' && event.investigated_by && event.investigated_by !== currentUser) ||
                    (event.status === 'resolved'      && event.resolved_by      && event.resolved_by      !== currentUser)
                  const lockedBy = event.investigated_by || event.resolved_by
                  return isLocked ? (
                    <p className="text-xs text-subtle font-mono flex items-center gap-1.5
                                  px-3 py-2 bg-surface rounded-lg border border-border/50">
                      <span className="text-medium">🔒</span>
                      Locked — being handled by
                      <span className="text-medium font-medium">{lockedBy}</span>
                    </p>
                  ) : (
                    <div className="flex gap-2">
                      {['open','investigating','resolved'].map(s => (
                        <button key={s} disabled={updating || event.status === s}
                          onClick={(e) => handleStatus(e, s)}
                          className={`text-xs px-3 py-1.5 rounded-lg border transition-all capitalize
                            ${event.status === s
                              ? 'bg-accent/20 text-accent border-accent/30 font-medium'
                              : 'text-dim border-border hover:border-accent/30 hover:text-text'
                            } disabled:opacity-40`}>
                          {s}
                        </button>
                      ))}
                    </div>
                  )
                })()}
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

// ── GroupCard ─────────────────────────────────────────────────────────────────
function GroupCard({ groupKey, events, groupByFields, selected, onSelect, onStatusChange, newEventIds }) {
  const [expanded,    setExpanded]    = useState(false)
  const [bulkStatus,  setBulkStatus]  = useState('')
  const [bulkLoading, setBulkLoading] = useState(false)
  const [sortField,   setSortField]   = useState('timestamp')
  const [sortDir,     setSortDir]     = useState('desc')

  const handleGroupSort = (field) => {
    if (sortField === field) setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    else { setSortField(field); setSortDir('asc') }
  }

  const SEVERITY_SORT_G = { critical: 0, high: 1, medium: 2, low: 3 }
  const sortedEvents = [...events].sort((a, b) => {
    let av = a[sortField] ?? ''
    let bv = b[sortField] ?? ''
    if (sortField === 'severity')  { av = SEVERITY_SORT_G[av] ?? 99; bv = SEVERITY_SORT_G[bv] ?? 99 }
    if (sortField === 'timestamp') { av = new Date(av + 'Z'); bv = new Date(bv + 'Z') }
    if (av < bv) return sortDir === 'asc' ? -1 : 1
    if (av > bv) return sortDir === 'asc' ?  1 : -1
    return 0
  })

  // Highest severity in group
  const topSeverity = events.reduce((best, e) =>
    (SEVERITY_ORDER[e.severity] ?? 99) < (SEVERITY_ORDER[best] ?? 99) ? e.severity : best
  , 'low')

  const openCount     = events.filter(e => e.status === 'open').length
  const investigating = events.filter(e => e.status === 'investigating').length
  const resolved      = events.filter(e => e.status === 'resolved').length
  const latest        = events[0]
  const groupSelected = events.every(e => selected.has(e.id))
  const someSelected  = events.some(e => selected.has(e.id))

  const toggleGroupSelect = (e) => {
    e.stopPropagation()
    if (groupSelected) {
      events.forEach(ev => onSelect(ev.id, true))
    } else {
      events.forEach(ev => onSelect(ev.id, false))
    }
  }

  const handleBulkUpdate = async (e) => {
    e.stopPropagation()
    if (!bulkStatus) return
    setBulkLoading(true)
    try {
      await Promise.all(events.map(ev => api.patch(`/events/${ev.id}/status`, { status: bulkStatus })))
      events.forEach(ev => onStatusChange({ ...ev, status: bulkStatus }))
      setBulkStatus('')
    } finally {
      setBulkLoading(false)
    }
  }

  // Build group label from groupByFields
  const labelParts = groupByFields.map(field => {
    const val = events[0]?.[field]
    return val ? (
      <span key={field} className="flex items-center gap-1">
        <span className="text-subtle text-[10px] uppercase font-mono">{field.replace('_',' ')}:</span>
        <span className="text-text font-medium">{val}</span>
      </span>
    ) : null
  }).filter(Boolean)

  const severityBorderColor = {
    critical: 'border-l-critical', high: 'border-l-high',
    medium: 'border-l-medium', low: 'border-l-low',
  }[topSeverity] ?? 'border-l-border'

  return (
    <div className={`card p-0 overflow-hidden border-l-2 ${severityBorderColor} mb-3 animate-fade-in`}>
      {/* Group header */}
      <div
        className="flex items-center gap-3 px-4 py-3 cursor-pointer hover:bg-muted/20
                   transition-colors"
        onClick={() => setExpanded(v => !v)}
      >
        {/* Group checkbox */}
        <div
          className={`shrink-0 transition-colors
                      ${groupSelected ? 'text-accent' : someSelected ? 'text-accent/50' : 'text-subtle hover:text-accent'}`}
          onClick={toggleGroupSelect}
        >
          {groupSelected ? <CheckSquare size={14} /> : <Square size={14} />}
        </div>

        {/* Severity */}
        <SeverityBadge severity={topSeverity} />

        {/* Group label */}
        <div className="flex items-center gap-3 flex-wrap flex-1 min-w-0">
          {labelParts}
        </div>

        {/* Stats */}
        <div className="flex items-center gap-3 shrink-0 ml-auto">
          <span className="text-xs font-mono text-dim">
            <span className="text-text font-medium">{events.length}</span> events
          </span>
          {openCount > 0 && (
            <span className="badge text-critical bg-critical/10 border border-critical/20">
              {openCount} open
            </span>
          )}
          {investigating > 0 && (
            <span className="badge text-medium bg-medium/10 border border-medium/20">
              {investigating} investigating
            </span>
          )}
          {resolved > 0 && (
            <span className="badge text-low bg-low/10 border border-low/20">
              {resolved} resolved
            </span>
          )}
          <span className="text-xs font-mono text-subtle">{formatTime(latest?.timestamp)}</span>
          {expanded ? <ChevronUp size={14} className="text-dim" /> : <ChevronDown size={14} className="text-dim" />}
        </div>
      </div>

      {/* Bulk action bar for group */}
      {expanded && (
        <div className="px-4 py-2 bg-surface/60 border-t border-border/50 flex items-center gap-2">
          <span className="text-xs text-subtle font-mono">Bulk update group:</span>
          {['open','investigating','resolved'].map(s => (
            <button key={s}
              onClick={e => { e.stopPropagation(); setBulkStatus(s) }}
              className={`text-xs px-2.5 py-1 rounded-lg border transition-all capitalize
                ${bulkStatus === s
                  ? 'bg-accent/20 text-accent border-accent/30'
                  : 'text-dim border-border hover:text-text'}`}>
              {s}
            </button>
          ))}
          <button onClick={handleBulkUpdate} disabled={!bulkStatus || bulkLoading}
            className="btn-primary text-xs px-3 py-1 disabled:opacity-40">
            {bulkLoading ? 'Updating...' : 'Apply'}
          </button>
        </div>
      )}

      {/* Expanded rows */}
      {expanded && (
        <div className="border-t border-border/50 overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border/50 bg-surface/40">
                <th className="w-8 px-3 py-2" />
                <SortableHeader label="Severity"  field="severity"    sortField={sortField} sortDir={sortDir} onSort={handleGroupSort} />
                <SortableHeader label="Type"      field="event_type"  sortField={sortField} sortDir={sortDir} onSort={handleGroupSort} />
                <SortableHeader label="Source IP" field="source_ip"   sortField={sortField} sortDir={sortDir} onSort={handleGroupSort} />
                <SortableHeader label="Target"    field="target_host" sortField={sortField} sortDir={sortDir} onSort={handleGroupSort} />
                <SortableHeader label="User"      field="username"    sortField={sortField} sortDir={sortDir} onSort={handleGroupSort} />
                <SortableHeader label="Status"    field="status"      sortField={sortField} sortDir={sortDir} onSort={handleGroupSort} />
                <th className="px-3 py-2 text-left font-mono text-subtle uppercase tracking-widest text-[10px]">Source</th>
                <SortableHeader label="Time"      field="timestamp"   sortField={sortField} sortDir={sortDir} onSort={handleGroupSort} />
                <th className="w-8 px-3 py-2" />
              </tr>
            </thead>
            <tbody>
              {sortedEvents.map(e => (
                <EventRow
                  key={e.id}
                  event={e}
                  selected={selected.has(e.id)}
                  onSelect={(id) => onSelect(id)}
                  onStatusChange={onStatusChange}
                  isNew={newEventIds.has(e.id)}
                  compact
                  currentUser={currentUser}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

// ── GroupBySelector ───────────────────────────────────────────────────────────
function GroupBySelector({ groupByFields, onChange }) {
  const [showAdd, setShowAdd] = useState(false)
  const available = GROUP_FIELDS.filter(f => !groupByFields.includes(f.value))

  const addField = (val) => {
    onChange([...groupByFields, val])
    setShowAdd(false)
  }

  const removeField = (val) => {
    onChange(groupByFields.filter(f => f !== val))
  }

  return (
    <div className="flex items-center gap-2 flex-wrap">
      <span className="text-xs font-mono text-subtle uppercase tracking-widest">Group by:</span>

      {groupByFields.map(f => {
        const label = GROUP_FIELDS.find(g => g.value === f)?.label ?? f
        return (
          <span key={f}
            className="flex items-center gap-1 text-xs font-mono px-2.5 py-1
                       bg-accent/15 text-accent border border-accent/25 rounded-lg">
            {label}
            <button onClick={() => removeField(f)} className="hover:text-white ml-0.5">
              <X size={10} />
            </button>
          </span>
        )
      })}

      {available.length > 0 && (
        <div className="relative">
          <button
            onClick={() => setShowAdd(v => !v)}
            className="flex items-center gap-1 text-xs font-mono px-2.5 py-1
                       text-subtle border border-dashed border-border rounded-lg
                       hover:text-dim hover:border-subtle transition-colors"
          >
            <Plus size={11} />
            Add field
          </button>
          {showAdd && (
            <div className="absolute top-full left-0 mt-1 bg-card border border-border
                            rounded-xl shadow-xl z-20 py-1 min-w-36 animate-slide-in">
              {available.map(f => (
                <button key={f.value} onClick={() => addField(f.value)}
                  className="w-full text-left px-3 py-2 text-xs text-dim hover:text-text
                             hover:bg-muted transition-colors font-mono">
                  {f.label}
                </button>
              ))}
            </div>
          )}
        </div>
      )}

      {groupByFields.length > 0 && (
        <button onClick={() => onChange([])}
          className="text-xs text-subtle hover:text-critical transition-colors font-mono flex items-center gap-1">
          <X size={10} /> Clear
        </button>
      )}
    </div>
  )
}

// ── Main Events Page ──────────────────────────────────────────────────────────
export default function Events() {
  const { user }                          = useAuth()
  const currentUser                       = user?.username
  const [events,        setEvents]        = useState([])
  const [hosts,         setHosts]         = useState([])
  const [loading,       setLoading]       = useState(true)
  const [totalCount,    setTotalCount]    = useState(0)
  const [severity,      setSeverity]      = useState('')
  const [status,        setStatus]        = useState('open')
  const [showResolved,  setShowResolved]  = useState(false)
  const [type,          setType]          = useState('')
  const [host,          setHost]          = useState('')
  const [source,        setSource]        = useState('')
  const [timeRange,     setTimeRange]     = useState('')
  const [dateFrom,      setDateFrom]      = useState('')
  const [dateTo,        setDateTo]        = useState('')
  const [search,        setSearch]        = useState('')
  const [selected,      setSelected]      = useState(new Set())
  const [bulkStatus,    setBulkStatus]    = useState('')
  const [bulkLoading,   setBulkLoading]   = useState(false)
  const [newEventIds,   setNewEventIds]   = useState(new Set())
  const [resolvedCount, setResolvedCount] = useState(0)
  const [autoRefresh,   setAutoRefresh]   = useState(false)
  const [viewMode,      setViewMode]      = useState('list')    // 'list' | 'grouped'
  const [sortField,     setSortField]     = useState('timestamp')
  const [sortDir,       setSortDir]       = useState('desc')       // 'asc' | 'desc'
  const [groupByFields, setGroupByFields] = useState(['event_type', 'source_ip'])
  const autoRefreshRef                    = useRef(null)

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

  useEffect(() => {
    if (autoRefresh) {
      autoRefreshRef.current = setInterval(fetchEvents, 30000)
    } else {
      clearInterval(autoRefreshRef.current)
    }
    return () => clearInterval(autoRefreshRef.current)
  }, [autoRefresh, fetchEvents])

  useSocket((event) => {
    setEvents(prev => [event, ...prev])
    const eid = event.id ?? `live-${Date.now()}`
    setNewEventIds(prev => new Set([...prev, eid]))
    setTimeout(() => setNewEventIds(prev => { const n = new Set(prev); n.delete(eid); return n }), 8000)
  }, null)

  const handleStatusChange = (updated) => {
    setEvents(prev => prev.map(e => e.id === updated.id ? updated : e))
  }

  const toggleSelect = (id, forceRemove = null) => {
    setSelected(prev => {
      const next = new Set(prev)
      if (forceRemove === true)       next.delete(id)
      else if (forceRemove === false) next.add(id)
      else next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  const toggleSelectAll = () => {
    if (selected.size === sorted.length) setSelected(new Set())
    else setSelected(new Set(sorted.map(e => e.id)))
  }

  const handleBulkUpdate = async () => {
    if (!bulkStatus || selected.size === 0) return
    setBulkLoading(true)
    try {
      await Promise.all([...selected].map(id => api.patch(`/events/${id}/status`, { status: bulkStatus })))
      setEvents(prev => prev.map(e => selected.has(e.id) ? { ...e, status: bulkStatus } : e))
      setSelected(new Set())
      setBulkStatus('')
    } finally {
      setBulkLoading(false)
    }
  }

  // Client-side filter (time + search)
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
      if (ts < Date.now() - parseInt(timeRange) * 3600000) return false
    }
    if (timeRange === 'custom') {
      if (dateFrom && ts < new Date(dateFrom).getTime()) return false
      if (dateTo   && ts > new Date(dateTo).getTime())   return false
    }
    return true
  })

  // Sort filtered events
  const SEVERITY_SORT = { critical: 0, high: 1, medium: 2, low: 3 }
  const sorted = [...filtered].sort((a, b) => {
    let av = a[sortField] ?? ''
    let bv = b[sortField] ?? ''
    if (sortField === 'severity') { av = SEVERITY_SORT[av] ?? 99; bv = SEVERITY_SORT[bv] ?? 99 }
    if (sortField === 'timestamp') { av = new Date(av+'Z'); bv = new Date(bv+'Z') }
    if (av < bv) return sortDir === 'asc' ? -1 : 1
    if (av > bv) return sortDir === 'asc' ?  1 : -1
    return 0
  })

  const handleSort = (field) => {
    if (sortField === field) setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    else { setSortField(field); setSortDir('asc') }
  }

  // Group filtered events
  const groups = groupByFields.length > 0
    ? Object.entries(
        filtered.reduce((acc, e) => {
          const key = groupByFields.map(f => e[f] ?? '—').join(' :: ')
          acc[key] = acc[key] ?? []
          acc[key].push(e)
          return acc
        }, {})
      ).sort((a, b) => {
        // Sort groups by worst severity first
        const worstSeverity = (evts) => Math.min(...evts.map(e => SEVERITY_ORDER[e.severity] ?? 99))
        return worstSeverity(a[1]) - worstSeverity(b[1])
      })
    : []

  const severityCounts = filtered.reduce((acc, e) => {
    acc[e.severity] = (acc[e.severity] ?? 0) + 1
    return acc
  }, {})

  const handleExport = () => {
    exportToCSV(
      filtered.map(e => ({
        timestamp: e.timestamp, severity: e.severity, event_type: e.event_type,
        source_ip: e.source_ip ?? '', target_host: e.target_host ?? '',
        username: e.username ?? '', description: e.description,
        status: e.status, source: e.source,
        mitre_technique: e.mitre_technique ?? '', mitre_tactic: e.mitre_tactic ?? '',
      })),
      `forensight-events-${new Date().toISOString().slice(0,10)}.csv`
    )
  }

  const toggleShowResolved = () => {
    if (showResolved) { setStatus('open'); setShowResolved(false) }
    else { setStatus(''); setShowResolved(true) }
  }

  const clearFilters = () => {
    setSeverity(''); setStatus('open'); setType('')
    setHost(''); setSource(''); setTimeRange('')
    setDateFrom(''); setDateTo(''); setSearch('')
    setShowResolved(false)
  }

  const hasFilters = severity || status !== 'open' || type || host || source || timeRange || search

  const chips = [
    severity  && { label: `Severity: ${severity}`,             clear: () => setSeverity('')  },
    status    && { label: `Status: ${status}`,                  clear: () => setStatus('')    },
    type      && { label: `Type: ${type.replace(/_/g,' ')}`,   clear: () => setType('')      },
    host      && { label: `Host: ${host}`,                      clear: () => setHost('')      },
    source    && { label: `Source: ${source}`,                  clear: () => setSource('')    },
    timeRange && { label: timeRange === 'custom'
                    ? `${dateFrom||'?'} → ${dateTo||'?'}`
                    : `Last ${timeRange}h`,
                   clear: () => { setTimeRange(''); setDateFrom(''); setDateTo('') }},
    search    && { label: `"${search}"`,                        clear: () => setSearch('')    },
  ].filter(Boolean)

  return (
    <div className="animate-fade-in">
      <PageHeader title="Events" subtitle={`Showing ${filtered.length} of ${totalCount} total events`}>
        {/* View toggle */}
        <div className="flex items-center bg-surface border border-border rounded-lg p-0.5">
          <button onClick={() => setViewMode('list')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs transition-all
                        ${viewMode === 'list' ? 'bg-accent/20 text-accent' : 'text-dim hover:text-text'}`}>
            <List size={13} /> List
          </button>
          <button onClick={() => setViewMode('grouped')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs transition-all
                        ${viewMode === 'grouped' ? 'bg-accent/20 text-accent' : 'text-dim hover:text-text'}`}>
            <Layers size={13} /> Grouped
          </button>
        </div>
        <button onClick={() => setAutoRefresh(v => !v)}
          className={`flex items-center gap-1.5 text-xs px-3 py-2 rounded-lg border transition-all font-mono
                      ${autoRefresh ? 'bg-low/10 text-low border-low/30' : 'text-dim border-border hover:text-text'}`}>
          <RefreshCw size={12} className={autoRefresh ? 'animate-spin' : ''} style={autoRefresh ? {animationDuration:'3s'} : {}} />
          {autoRefresh ? 'Auto' : 'Auto off'}
        </button>
        <button onClick={handleExport} disabled={filtered.length === 0}
          className="btn-ghost flex items-center gap-1.5 disabled:opacity-40">
          <Download size={13} /> Export CSV
        </button>
        <button onClick={fetchEvents} className="btn-ghost flex items-center gap-1.5">
          <RefreshCw size={13} /> Refresh
        </button>
      </PageHeader>

      {/* Severity badges */}
      {filtered.length > 0 && (
        <div className="flex gap-2 mb-4 flex-wrap">
          {['critical','high','medium','low'].map(s => severityCounts[s] ? (
            <span key={s} onClick={() => setSeverity(s)}
              className={`badge border cursor-pointer hover:opacity-80 transition-opacity
                ${s==='critical' ? 'text-critical bg-critical/10 border-critical/20' :
                  s==='high'     ? 'text-high bg-high/10 border-high/20' :
                  s==='medium'   ? 'text-medium bg-medium/10 border-medium/20' :
                                   'text-low bg-low/10 border-low/20'}`}>
              {severityCounts[s]} {s}
            </span>
          ) : null)}
        </div>
      )}

      {/* Resolved toggle */}
      <div className="flex items-center gap-3 mb-4">
        <button onClick={toggleShowResolved}
          className={`text-xs font-mono px-3 py-1.5 rounded-lg border transition-all flex items-center gap-1.5
                      ${showResolved ? 'bg-low/10 text-low border-low/20' : 'text-subtle border-border hover:text-dim hover:border-subtle'}`}>
          {showResolved ? '✓ Showing resolved' : 'Show resolved'}
          {!showResolved && resolvedCount > 0 && (
            <span className="bg-muted text-text px-1.5 py-0.5 rounded font-mono text-[10px] ml-0.5 font-medium">
              {resolvedCount}
            </span>
          )}
        </button>
      </div>

      {/* Filters card */}
      <div className="card mb-4 p-4">
        <div className="flex items-center gap-2 mb-3">
          <Filter size={13} className="text-subtle" />
          <span className="text-xs font-mono text-subtle uppercase tracking-widest">Filters</span>
          {hasFilters && (
            <button onClick={clearFilters}
              className="ml-auto text-xs text-dim hover:text-critical flex items-center gap-1 transition-colors">
              <X size={11} /> Clear all
            </button>
          )}
        </div>

        <div className="flex gap-3 flex-wrap mb-3">
          <Select value={severity}  onChange={setSeverity}  options={SEVERITY_OPTIONS} className="w-36" />
          <Select value={status} onChange={v => { setStatus(v); setShowResolved(v===''||v==='resolved') }}
            options={STATUS_OPTIONS} className="w-36" />
          <Select value={type}      onChange={setType}      options={TYPE_OPTIONS}     className="w-48" />
          <Select value={host}      onChange={setHost}      options={hosts}            className="w-40" />
          <Select value={source}    onChange={setSource}    options={SOURCE_OPTIONS}   className="w-36" />
          <Select value={timeRange} onChange={setTimeRange} options={TIME_OPTIONS}     className="w-40" />
        </div>

        {timeRange === 'custom' && (
          <div className="flex gap-3 flex-wrap mb-3 animate-slide-in">
            <div className="flex items-center gap-2">
              <label className="text-xs text-dim font-mono whitespace-nowrap">From</label>
              <input type="datetime-local" value={dateFrom} onChange={e => setDateFrom(e.target.value)}
                className="input w-52 text-xs" />
            </div>
            <div className="flex items-center gap-2">
              <label className="text-xs text-dim font-mono whitespace-nowrap">To</label>
              <input type="datetime-local" value={dateTo} onChange={e => setDateTo(e.target.value)}
                className="input w-52 text-xs" />
            </div>
          </div>
        )}

        <div className="relative mb-3">
          <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-subtle" />
          <input className="input pl-8 pr-8"
            placeholder="Search description, IP, username, host, event type..."
            value={search} onChange={e => setSearch(e.target.value)} />
          {search && (
            <button onClick={() => setSearch('')}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-subtle hover:text-dim">
              <X size={12} />
            </button>
          )}
        </div>

        {/* Group by selector — only shown in grouped mode */}
        {viewMode === 'grouped' && (
          <div className="pt-3 border-t border-border/50">
            <GroupBySelector groupByFields={groupByFields} onChange={setGroupByFields} />
          </div>
        )}

        {chips.length > 0 && (
          <div className="flex gap-2 flex-wrap mt-3">
            {chips.map((chip, i) => (
              <span key={i} className="flex items-center gap-1 text-xs font-mono px-2 py-1
                                       bg-accent/10 text-accent border border-accent/20 rounded-lg">
                {chip.label}
                <button onClick={chip.clear} className="hover:text-white ml-0.5"><X size={10} /></button>
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
              <button key={s} onClick={() => setBulkStatus(s)}
                className={`text-xs px-3 py-1.5 rounded-lg border transition-all capitalize
                  ${bulkStatus===s ? 'bg-accent/20 text-accent border-accent/30 font-medium'
                                   : 'text-dim border-border hover:border-accent/30 hover:text-text'}`}>
                {s}
              </button>
            ))}
            <button onClick={handleBulkUpdate} disabled={!bulkStatus || bulkLoading}
              className="btn-primary text-xs disabled:opacity-40">
              {bulkLoading ? 'Updating...' : 'Apply'}
            </button>
            <button onClick={() => { setSelected(new Set()); setBulkStatus('') }}
              className="text-subtle hover:text-dim"><X size={14} /></button>
          </div>
        </div>
      )}

      {/* Content */}
      {loading ? (
        <SkeletonTable rows={8} cols={10} />
      ) : filtered.length === 0 ? (
        <div className="card"><EmptyState icon={Filter} message="No events match your filters" /></div>

      ) : viewMode === 'list' ? (
        // ── List View ──
        <div className="card p-0 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-surface/60">
                  <th className="px-3 py-3 w-8" onClick={toggleSelectAll}>
                    <div className={`cursor-pointer transition-colors
                                     ${selected.size===sorted.length && sorted.length>0 ? 'text-accent' : 'text-subtle hover:text-dim'}`}>
                      {selected.size===sorted.length && sorted.length>0
                        ? <CheckSquare size={14} /> : <Square size={14} />}
                    </div>
                  </th>
                  <SortableHeader label="Severity"  field="severity"    sortField={sortField} sortDir={sortDir} onSort={handleSort} />
                  <SortableHeader label="Type"      field="event_type"  sortField={sortField} sortDir={sortDir} onSort={handleSort} />
                  <SortableHeader label="Source IP" field="source_ip"   sortField={sortField} sortDir={sortDir} onSort={handleSort} />
                  <SortableHeader label="Target"    field="target_host" sortField={sortField} sortDir={sortDir} onSort={handleSort} />
                  <SortableHeader label="User"      field="username"    sortField={sortField} sortDir={sortDir} onSort={handleSort} />
                  <SortableHeader label="Status"    field="status"      sortField={sortField} sortDir={sortDir} onSort={handleSort} />
                  <th className="px-4 py-3 text-left text-xs font-mono text-subtle uppercase tracking-widest font-medium">Source</th>
                  <SortableHeader label="Time"      field="timestamp"   sortField={sortField} sortDir={sortDir} onSort={handleSort} />
                  <th className="px-4 py-3 w-8" />
                </tr>
              </thead>
              <tbody>
                {sorted.map(e => (
                  <EventRow key={e.id} event={e} selected={selected.has(e.id)}
                    onSelect={toggleSelect} onStatusChange={handleStatusChange}
                    isNew={newEventIds.has(e.id)} currentUser={currentUser} />
                ))}
              </tbody>
            </table>
          </div>
        </div>

      ) : (
        // ── Grouped View ──
        groupByFields.length === 0 ? (
          <div className="card border-accent/20 bg-accent/5 text-center py-8">
            <Layers size={24} className="text-subtle mx-auto mb-2" />
            <p className="text-sm text-dim">Select at least one field to group by above</p>
          </div>
        ) : (
          <div>
            <p className="text-xs text-subtle font-mono mb-3">
              {groups.length} group{groups.length !== 1 ? 's' : ''} · {filtered.length} events
            </p>
            {groups.map(([key, evts]) => (
              <GroupCard
                key={key}
                groupKey={key}
                events={evts}
                groupByFields={groupByFields}
                selected={selected}
                onSelect={toggleSelect}
                onStatusChange={handleStatusChange}
                newEventIds={newEventIds}
              />
            ))}
          </div>
        )
      )}
    </div>
  )
}
