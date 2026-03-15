import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Monitor, Activity, ShieldAlert, ArrowRight } from 'lucide-react'
import api from '../utils/api'
import { PageHeader, EmptyState } from '../components/ui'
import { SkeletonHostCard } from '../components/ui/Skeleton'

function HostCard({ host, onClick }) {
  const [stats,   setStats]   = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.get('/stats', { params: { target_host: host } })
      .then(r => setStats(r.data))
      .finally(() => setLoading(false))
  }, [host])

  return (
    <div
      onClick={onClick}
      className="card cursor-pointer hover:border-accent/40 transition-all
                 duration-200 group"
    >
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-accent/10 border border-accent/20
                          flex items-center justify-center">
            <Monitor size={16} className="text-accent" />
          </div>
          <div>
            <p className="font-display font-semibold text-text">{host}</p>
            <p className="text-xs text-subtle font-mono">log source</p>
          </div>
        </div>
        <ArrowRight size={14} className="text-subtle group-hover:text-accent
                                         transition-colors mt-1" />
      </div>

      {loading ? (
        <div className="flex gap-4">
          {[1,2,3].map(i => (
            <div key={i} className="h-8 flex-1 bg-muted/50 rounded-lg animate-pulse" />
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-3 gap-3">
          <div className="text-center p-2 bg-surface rounded-lg">
            <p className="text-lg font-display font-bold text-text">
              {stats?.total_logs?.toLocaleString() ?? 0}
            </p>
            <p className="text-xs text-subtle font-mono">logs</p>
          </div>
          <div className="text-center p-2 bg-surface rounded-lg">
            <p className="text-lg font-display font-bold text-text">
              {stats?.total_events ?? 0}
            </p>
            <p className="text-xs text-subtle font-mono">events</p>
          </div>
          <div className="text-center p-2 bg-surface rounded-lg">
            <p className={`text-lg font-display font-bold ${
              stats?.open_alerts > 0 ? 'text-high' : 'text-low'
            }`}>
              {stats?.open_alerts ?? 0}
            </p>
            <p className="text-xs text-subtle font-mono">open</p>
          </div>
        </div>
      )}

      {/* Severity bar */}
      {stats && (
        <div className="mt-3 flex gap-0.5 h-1 rounded-full overflow-hidden">
          {[
            { key: 'critical', color: 'bg-critical' },
            { key: 'high',     color: 'bg-high'     },
            { key: 'medium',   color: 'bg-medium'   },
            { key: 'low',      color: 'bg-low'      },
          ].map(({ key, color }) => {
            const total = stats.total_events || 1
            const pct   = (stats.by_severity?.[key] ?? 0) / total * 100
            return pct > 0 ? (
              <div key={key} className={`${color}`} style={{ width: `${pct}%` }} />
            ) : null
          })}
        </div>
      )}
    </div>
  )
}

export default function Hosts() {
  const [hosts,   setHosts]   = useState([])
  const [loading, setLoading] = useState(true)
  const navigate              = useNavigate()

  useEffect(() => {
    api.get('/hosts')
      .then(r => setHosts(r.data))
      .finally(() => setLoading(false))
  }, [])

  if (loading) return (
    <div className="animate-fade-in">
      <div className="h-7 bg-muted/60 rounded w-24 mb-6 animate-pulse" />
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {[1,2,3].map(i => <SkeletonHostCard key={i} />)}
      </div>
    </div>
  )

  return (
    <div className="animate-fade-in">
      <PageHeader
        title="Hosts"
        subtitle={`${hosts.length} monitored host${hosts.length !== 1 ? 's' : ''}`}
      />

      {hosts.length === 0 ? (
        <EmptyState icon={Monitor} message="No hosts connected yet" />
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {hosts.map(h => (
            <HostCard
              key={h}
              host={h}
              onClick={() => navigate(`/events?host=${h}`)}
            />
          ))}
        </div>
      )}
    </div>
  )
}
