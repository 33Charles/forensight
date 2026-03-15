import { useEffect, useState, useCallback, useRef } from 'react'
import { RefreshCw, Radio, Filter, X, Download } from 'lucide-react'
import api from '../utils/api'
import { useSocket } from '../hooks/useSocket'
import { PageHeader, EmptyState, Select } from '../components/ui'
import { SkeletonTable } from '../components/ui/Skeleton'
import { formatTime } from '../utils/helpers'
import { exportToCSV } from '../utils/export'

const TYPE_OPTIONS = [
  { value: '',            label: 'All types'   },
  { value: 'ssh',         label: 'SSH'         },
  { value: 'sudo',        label: 'Sudo'        },
  { value: 'file_access', label: 'File Access' },
  { value: 'network',     label: 'Network'     },
  { value: 'auth',        label: 'Auth'        },
  { value: 'system',      label: 'System'      },
]

const SOURCE_OPTIONS = [
  { value: '',            label: 'All sources' },
  { value: 'live',        label: 'Live'        },
  { value: 'historical',  label: 'Historical'  },
]

const TYPE_COLORS = {
  ssh:         'text-info',
  sudo:        'text-medium',
  file_access: 'text-high',
  network:     'text-accent',
  auth:        'text-low',
  system:      'text-dim',
}

export default function Logs() {
  const [logs,    setLogs]    = useState([])
  const [hosts,   setHosts]   = useState([])
  const [loading, setLoading] = useState(true)
  const [logType, setLogType] = useState('')
  const [source,  setSource]  = useState('')
  const [host,    setHost]    = useState('')
  const [search,  setSearch]  = useState('')
  const [live,    setLive]    = useState(false)
  const bottomRef             = useRef(null)

  useEffect(() => {
    api.get('/hosts').then(r =>
      setHosts([{ value: '', label: 'All hosts' },
                ...r.data.map(h => ({ value: h, label: h }))])
    )
  }, [])

  const fetchLogs = useCallback(async () => {
    setLoading(true)
    try {
      const params = { limit: 300 }
      if (logType) params.log_type = logType
      if (source)  params.source   = source
      if (host)    params.host     = host
      const { data } = await api.get('/logs', { params })
      setLogs(data)
    } finally {
      setLoading(false)
    }
  }, [logType, source, host])

  useEffect(() => { fetchLogs() }, [fetchLogs])

  useSocket(null, (entry) => {
    if (!live) return
    setLogs(prev => [entry, ...prev].slice(0, 500))
  })

  useEffect(() => {
    if (live) bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [logs, live])

  const filtered = search
    ? logs.filter(l =>
        l.message?.toLowerCase().includes(search.toLowerCase()) ||
        l.host?.toLowerCase().includes(search.toLowerCase()) ||
        l.process?.toLowerCase().includes(search.toLowerCase())
      )
    : logs

  const handleExport = () => {
    exportToCSV(
      filtered.map(l => ({
        timestamp: l.timestamp,
        host:      l.host,
        process:   l.process,
        log_type:  l.log_type,
        source:    l.source,
        message:   l.message,
      })),
      `forensight-logs-${new Date().toISOString().slice(0,10)}.csv`
    )
  }

  return (
    <div className="animate-fade-in">
      <PageHeader title="Logs" subtitle={`${filtered.length} entries`}>
        <button
          onClick={handleExport}
          disabled={filtered.length === 0}
          className="btn-ghost flex items-center gap-1.5 disabled:opacity-40"
        >
          <Download size={13} />
          Export CSV
        </button>
        <button
          onClick={() => setLive(v => !v)}
          className={`flex items-center gap-1.5 text-xs px-3 py-2 rounded-lg border
                      transition-all font-mono
                      ${live
                        ? 'bg-low/10 text-low border-low/30'
                        : 'text-dim border-border hover:text-text'
                      }`}
        >
          <Radio size={12} className={live ? 'animate-pulse' : ''} />
          {live ? 'LIVE' : 'Live off'}
        </button>
        <button onClick={fetchLogs} className="btn-ghost flex items-center gap-1.5">
          <RefreshCw size={13} />
          Refresh
        </button>
      </PageHeader>

      {/* Filters */}
      <div className="flex gap-3 mb-4 flex-wrap items-center">
        <Filter size={14} className="text-subtle" />
        <Select value={logType} onChange={setLogType} options={TYPE_OPTIONS}   className="w-36" />
        <Select value={source}  onChange={setSource}  options={SOURCE_OPTIONS} className="w-36" />
        <Select value={host}    onChange={setHost}    options={hosts}          className="w-40" />
        <div className="relative flex-1 max-w-xs">
          <input
            className="input pr-8"
            placeholder="Search messages..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
          {search && (
            <button
              onClick={() => setSearch('')}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-subtle hover:text-dim"
            >
              <X size={12} />
            </button>
          )}
        </div>
      </div>

      {loading ? (
        <SkeletonTable rows={10} cols={5} />
      ) : (
        <div className="card p-0 overflow-hidden">
          {/* Terminal header */}
          <div className="bg-surface/80 px-4 py-2.5 border-b border-border flex items-center gap-2">
            <div className="flex gap-1.5">
              <div className="w-3 h-3 rounded-full bg-critical/60" />
              <div className="w-3 h-3 rounded-full bg-medium/60" />
              <div className="w-3 h-3 rounded-full bg-low/60" />
            </div>
            <span className="text-xs font-mono text-subtle ml-2">forensight.log</span>
            {live && (
              <span className="ml-auto text-xs font-mono text-low flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-low animate-pulse" />
                streaming
              </span>
            )}
          </div>

          <div className="overflow-auto max-h-[62vh] bg-bg/50">
            {filtered.length === 0 ? (
              <EmptyState message="No logs found" />
            ) : (
              <table className="w-full text-xs font-mono">
                <thead className="sticky top-0 bg-surface/95 backdrop-blur-sm">
                  <tr className="border-b border-border/50">
                    {['Time','Host','Type','Process','Message'].map(h => (
                      <th key={h} className="px-4 py-2.5 text-left text-subtle uppercase
                                             tracking-widest text-[10px] font-medium">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((l, i) => (
                    <tr key={l.id ?? i}
                        className="border-b border-border/20 hover:bg-muted/20 transition-colors">
                      <td className="px-4 py-2 text-subtle whitespace-nowrap">{formatTime(l.timestamp)}</td>
                      <td className="px-4 py-2 text-accent whitespace-nowrap">{l.host}</td>
                      <td className="px-4 py-2 whitespace-nowrap">
                        <span className={TYPE_COLORS[l.log_type] ?? 'text-dim'}>{l.log_type}</span>
                      </td>
                      <td className="px-4 py-2 text-dim whitespace-nowrap">{l.process}</td>
                      <td className="px-4 py-2 text-text/80 max-w-xl truncate">{l.message}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            <div ref={bottomRef} />
          </div>
        </div>
      )}
    </div>
  )
}
