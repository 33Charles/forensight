import { useEffect, useState, useCallback } from 'react'
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  CartesianGrid, BarChart, Bar, Cell, PieChart, Pie, Legend
} from 'recharts'
import { ShieldAlert, Activity, AlertTriangle, ScrollText, Zap, Target } from 'lucide-react'
import api from '../utils/api'
import { useSocket } from '../hooks/useSocket'
import { useToast } from '../context/ToastContext'
import {
  StatCard, SeverityBadge, PageHeader, EmptyState
} from '../components/ui'
import { SkeletonCard, SkeletonChart } from '../components/ui/Skeleton'
import { formatTime, severityColor, timeAgo, formatEventType } from '../utils/helpers'

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-card border border-border rounded-lg px-3 py-2 text-xs font-mono">
      <p className="text-dim mb-1">{label}</p>
      {payload.map(p => (
        <p key={p.name} style={{ color: p.color }}>{p.name}: {p.value}</p>
      ))}
    </div>
  )
}

const SEVERITY_PIE = [
  { key: 'critical', color: '#ef4444' },
  { key: 'high',     color: '#f97316' },
  { key: 'medium',   color: '#eab308' },
  { key: 'low',      color: '#22c55e' },
]

export default function Dashboard() {
  const [stats,     setStats]     = useState(null)
  const [timeline,  setTimeline]  = useState([])
  const [attackers, setAttackers] = useState([])
  const [targets,   setTargets]   = useState([])
  const [recent,    setRecent]    = useState([])
  const [loading,   setLoading]   = useState(true)

  const fetchAll = useCallback(async () => {
    try {
      const [s, t, a, tg, r] = await Promise.all([
        api.get('/stats'),
        api.get('/events/timeline'),
        api.get('/events/top-attackers'),
        api.get('/events/top-targets'),
        api.get('/events?limit=8'),
      ])
      setStats(s.data)
      setTimeline(t.data.map(d => ({ ...d, hour: d.hour.split(' ')[1] })))
      setAttackers(a.data)
      setTargets(tg.data)
      setRecent(r.data)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { fetchAll() }, [fetchAll])

  useSocket(
    (event) => {
      setRecent(prev => [event, ...prev].slice(0, 8))
      setStats(prev => prev ? {
        ...prev,
        total_events: prev.total_events + 1,
        open_alerts:  prev.open_alerts + 1,
        by_severity: {
          ...prev.by_severity,
          [event.severity]: (prev.by_severity[event.severity] ?? 0) + 1,
        },
        by_type: {
          ...prev.by_type,
          [event.event_type]: (prev.by_type?.[event.event_type] ?? 0) + 1,
        }
      } : prev)
    },
    null
  )

  // Severity pie data
  const pieData = SEVERITY_PIE.map(({ key, color }) => ({
    name: key,
    value: stats?.by_severity?.[key] ?? 0,
    color,
  })).filter(d => d.value > 0)

  // Event type bar data
  const typeData = Object.entries(stats?.by_type ?? {})
    .filter(([, v]) => v > 0)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([k, v]) => ({ name: formatEventType(k), value: v }))

  if (loading) return (
    <div className="animate-fade-in">
      <div className="mb-6">
        <div className="h-7 bg-muted/60 rounded w-32 mb-2 animate-pulse" />
        <div className="h-4 bg-muted/40 rounded w-48 animate-pulse" />
      </div>
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        {[1,2,3,4].map(i => <SkeletonCard key={i} />)}
      </div>
      <SkeletonChart />
    </div>
  )

  return (
    <div className="animate-fade-in">
      <PageHeader title="Dashboard" subtitle="Security event overview — last 24 hours" />

      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <StatCard label="Total Logs"   value={stats?.total_logs?.toLocaleString()}   icon={ScrollText}    color="accent"   />
        <StatCard label="Total Events" value={stats?.total_events?.toLocaleString()} icon={Activity}      color="accent"   />
        <StatCard label="Open Alerts"  value={stats?.open_alerts?.toLocaleString()}  icon={AlertTriangle} color="high"     />
        <StatCard label="Critical"     value={stats?.by_severity?.critical}           icon={ShieldAlert}   color="critical" />
      </div>

      {/* Timeline */}
      <div className="card mb-6">
        <h2 className="text-sm font-display font-semibold text-text mb-4">
          Event Timeline · Last 24h
        </h2>
        <ResponsiveContainer width="100%" height={200}>
          <AreaChart data={timeline} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
            <defs>
              {['critical','high','medium','low'].map(s => (
                <linearGradient key={s} id={`grad-${s}`} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor={severityColor(s)} stopOpacity={0.3} />
                  <stop offset="95%" stopColor={severityColor(s)} stopOpacity={0}   />
                </linearGradient>
              ))}
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#1e2538" />
            <XAxis dataKey="hour" tick={{ fill: '#4a5578', fontSize: 10, fontFamily: 'JetBrains Mono' }} />
            <YAxis tick={{ fill: '#4a5578', fontSize: 10, fontFamily: 'JetBrains Mono' }} />
            <Tooltip content={<CustomTooltip />} />
            {['critical','high','medium','low'].map(s => (
              <Area key={s} type="monotone" dataKey={s}
                    stroke={severityColor(s)} strokeWidth={1.5}
                    fill={`url(#grad-${s})`} />
            ))}
          </AreaChart>
        </ResponsiveContainer>
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-6">
        {/* Event types bar chart */}
        <div className="card">
          <h2 className="text-sm font-display font-semibold text-text mb-4">
            Events by Type
          </h2>
          {typeData.length === 0 ? (
            <EmptyState message="No event data" />
          ) : (
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={typeData} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e2538" />
                <XAxis dataKey="name" tick={{ fill: '#4a5578', fontSize: 9, fontFamily: 'JetBrains Mono' }}
                       angle={-20} textAnchor="end" height={40} />
                <YAxis tick={{ fill: '#4a5578', fontSize: 10, fontFamily: 'JetBrains Mono' }} />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                  {typeData.map((_, i) => (
                    <Cell key={i} fill="#6366f1" fillOpacity={0.7 - i * 0.06} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Severity donut */}
        <div className="card">
          <h2 className="text-sm font-display font-semibold text-text mb-4">
            Severity Breakdown
          </h2>
          {pieData.length === 0 ? (
            <EmptyState message="No event data" />
          ) : (
            <ResponsiveContainer width="100%" height={180}>
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={45}
                  outerRadius={70}
                  paddingAngle={3}
                  dataKey="value"
                >
                  {pieData.map((entry, i) => (
                    <Cell key={i} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  formatter={(v, n) => [v, n]}
                  contentStyle={{
                    background: '#141826', border: '1px solid #1e2538',
                    borderRadius: '8px', fontSize: '12px', fontFamily: 'JetBrains Mono'
                  }}
                />
                <Legend
                  formatter={(v) => (
                    <span style={{ color: '#8892a4', fontSize: '11px', fontFamily: 'JetBrains Mono' }}>
                      {v}
                    </span>
                  )}
                />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Bottom row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Recent alerts */}
        <div className="card lg:col-span-1">
          <h2 className="text-sm font-display font-semibold text-text mb-3 flex items-center gap-2">
            <Zap size={14} className="text-accent" />
            Recent Alerts
          </h2>
          {recent.length === 0 ? (
            <EmptyState message="No alerts yet" />
          ) : (
            <div className="space-y-2">
              {recent.map((e, i) => (
                <div key={e.id ?? i}
                     className="flex items-start gap-2.5 py-2 border-b border-border/50
                                last:border-0 animate-slide-in">
                  <SeverityBadge severity={e.severity} />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs text-text font-medium truncate">{e.description}</p>
                    <p className="text-xs text-subtle font-mono mt-0.5">{timeAgo(e.timestamp)}</p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Top attackers */}
        <div className="card">
          <h2 className="text-sm font-display font-semibold text-text mb-3 flex items-center gap-2">
            <AlertTriangle size={14} className="text-high" />
            Top Attackers
          </h2>
          {attackers.length === 0 ? (
            <EmptyState message="No data" />
          ) : (
            <div className="space-y-2.5">
              {attackers.map((a, i) => (
                <div key={a.ip} className="flex items-center gap-3">
                  <span className="text-xs text-subtle font-mono w-4">{i+1}</span>
                  <span className="flex-1 text-xs font-mono text-text">{a.ip}</span>
                  <div className="flex items-center gap-2">
                    <div className="h-1 bg-critical/60 rounded-full"
                         style={{ width: `${Math.max(8, (a.count/attackers[0].count)*80)}px` }} />
                    <span className="text-xs text-dim font-mono">{a.count}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Top targets */}
        <div className="card">
          <h2 className="text-sm font-display font-semibold text-text mb-3 flex items-center gap-2">
            <Target size={14} className="text-medium" />
            Top Targets
          </h2>
          {targets.length === 0 ? (
            <EmptyState message="No data" />
          ) : (
            <div className="space-y-2.5">
              {targets.map((t, i) => (
                <div key={t.username} className="flex items-center gap-3">
                  <span className="text-xs text-subtle font-mono w-4">{i+1}</span>
                  <span className="flex-1 text-xs font-mono text-text">{t.username}</span>
                  <div className="flex items-center gap-2">
                    <div className="h-1 bg-medium/60 rounded-full"
                         style={{ width: `${Math.max(8, (t.count/targets[0].count)*80)}px` }} />
                    <span className="text-xs text-dim font-mono">{t.count}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
