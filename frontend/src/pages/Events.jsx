import { useEffect, useState, useCallback } from 'react'
import { ChevronDown, ChevronUp, RefreshCw, Filter, Download } from 'lucide-react'
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
  { value: '',                        label: 'All types'              },
  { value: 'brute_force',             label: 'Brute Force'           },
  { value: 'brute_force_success',     label: 'Brute Force Success'   },
  { value: 'root_login_attempt',      label: 'Root Login'            },
  { value: 'privilege_escalation',    label: 'Privilege Escalation'  },
  { value: 'unauthorized_sudo',       label: 'Unauthorized Sudo'     },
  { value: 'sudo_brute_force',        label: 'Sudo Brute Force'      },
  { value: 'sensitive_file_access',   label: 'Sensitive File'        },
  { value: 'unauthorized_file_access',label: 'Unauthorized File'     },
  { value: 'port_scan',               label: 'Port Scan'             },
  { value: 'reverse_shell',           label: 'Reverse Shell'         },
  { value: 'c2_connection',           label: 'C2 Beaconing'          },
  { value: 'ssh_login_success',       label: 'SSH Login'             },
]

function EventRow({ event, onStatusChange }) {
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
        className="border-b border-border/50 hover:bg-muted/30 cursor-pointer
                   transition-colors animate-fade-in"
        onClick={() => setExpanded(v => !v)}
      >
        <td className="px-4 py-3"><SeverityBadge severity={event.severity} /></td>
        <td className="px-4 py-3"><EventTypeBadge type={event.event_type} /></td>
        <td className="px-4 py-3 text-xs font-mono text-dim">{event.source_ip ?? '—'}</td>
        <td className="px-4 py-3 text-xs font-mono text-dim">{event.target_host ?? '—'}</td>
        <td className="px-4 py-3 text-xs font-mono text-dim">{event.username ?? '—'}</td>
        <td className="px-4 py-3"><StatusBadge status={event.status} /></td>
        <td className="px-4 py-3 text-xs font-mono text-subtle whitespace-nowrap">
          {formatTime(event.timestamp)}
        </td>
        <td className="px-4 py-3 text-dim">
          {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
        </td>
      </tr>

      {expanded && (
        <tr className="bg-surface/50 border-b border-border animate-slide-in">
          <td colSpan={8} className="px-4 py-4">
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
  const [events,   setEvents]   = useState([])
  const [hosts,    setHosts]    = useState([])
  const [loading,  setLoading]  = useState(true)
  const [severity, setSeverity] = useState('')
  const [status,   setStatus]   = useState('')
  const [type,     setType]     = useState('')
  const [host,     setHost]     = useState('')

  // Load hosts for filter dropdown
  useEffect(() => {
    api.get('/hosts').then(r =>
      setHosts([{ value: '', label: 'All hosts' },
                ...r.data.map(h => ({ value: h, label: h }))])
    )
  }, [])

  const fetchEvents = useCallback(async () => {
    setLoading(true)
    try {
      const params = { limit: 200 }
      if (severity) params.severity    = severity
      if (status)   params.status      = status
      if (type)     params.event_type  = type
      if (host)     params.target_host = host
      const { data } = await api.get('/events', { params })
      setEvents(data)
    } finally {
      setLoading(false)
    }
  }, [severity, status, type, host])

  useEffect(() => { fetchEvents() }, [fetchEvents])

  useSocket(
    (event) => setEvents(prev => [event, ...prev]),
    null
  )

  const handleStatusChange = (updated) => {
    setEvents(prev => prev.map(e => e.id === updated.id ? updated : e))
  }

  const handleExport = () => {
    exportToCSV(
      events.map(e => ({
        timestamp:       e.timestamp,
        severity:        e.severity,
        event_type:      e.event_type,
        source_ip:       e.source_ip ?? '',
        target_host:     e.target_host ?? '',
        username:        e.username ?? '',
        description:     e.description,
        status:          e.status,
        mitre_technique: e.mitre_technique ?? '',
        mitre_tactic:    e.mitre_tactic ?? '',
      })),
      `forensight-events-${new Date().toISOString().slice(0,10)}.csv`
    )
  }

  return (
    <div className="animate-fade-in">
      <PageHeader title="Events" subtitle={`${events.length} events`}>
        <button
          onClick={handleExport}
          disabled={events.length === 0}
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

      {/* Filters */}
      <div className="flex gap-3 mb-5 flex-wrap items-center">
        <Filter size={14} className="text-subtle" />
        <Select value={severity} onChange={setSeverity} options={SEVERITY_OPTIONS} className="w-36" />
        <Select value={status}   onChange={setStatus}   options={STATUS_OPTIONS}   className="w-36" />
        <Select value={type}     onChange={setType}     options={TYPE_OPTIONS}     className="w-48" />
        <Select value={host}     onChange={setHost}     options={hosts}            className="w-40" />
      </div>

      {loading ? (
        <SkeletonTable rows={8} cols={8} />
      ) : events.length === 0 ? (
        <div className="card">
          <EmptyState icon={Filter} message="No events match your filters" />
        </div>
      ) : (
        <div className="card p-0 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-surface/60">
                  {['Severity','Type','Source IP','Target','User','Status','Time',''].map(h => (
                    <th key={h} className="px-4 py-3 text-left text-xs font-mono
                                           text-subtle uppercase tracking-widest font-medium">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {events.map(e => (
                  <EventRow key={e.id} event={e} onStatusChange={handleStatusChange} />
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
