import { severityClass, statusClass, formatEventType } from '../../utils/helpers'

export function SeverityBadge({ severity }) {
  return (
    <span className={`badge ${severityClass(severity)}`}>
      {severity}
    </span>
  )
}

export function StatusBadge({ status }) {
  return (
    <span className={`badge ${statusClass(status)}`}>
      {status}
    </span>
  )
}

export function EventTypeBadge({ type }) {
  return (
    <span className="badge bg-accent/10 text-accent border border-accent/20 capitalize">
      {formatEventType(type)}
    </span>
  )
}

export function Spinner({ size = 16 }) {
  return (
    <svg
      className="animate-spin text-accent"
      width={size} height={size}
      viewBox="0 0 24 24" fill="none"
    >
      <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="2"
              strokeOpacity="0.2" />
      <path d="M12 2a10 10 0 0 1 10 10" stroke="currentColor" strokeWidth="2"
            strokeLinecap="round" />
    </svg>
  )
}

export function PageHeader({ title, subtitle, children }) {
  return (
    <div className="flex items-start justify-between mb-6">
      <div>
        <h1 className="font-display text-2xl font-bold text-text">{title}</h1>
        {subtitle && <p className="text-sm text-dim mt-1">{subtitle}</p>}
      </div>
      {children && <div className="flex items-center gap-2">{children}</div>}
    </div>
  )
}

export function EmptyState({ icon: Icon, message }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-dim gap-3">
      {Icon && <Icon size={32} strokeWidth={1} className="text-subtle" />}
      <p className="text-sm">{message}</p>
    </div>
  )
}

export function StatCard({ label, value, icon: Icon, color = 'accent', delta }) {
  const colorMap = {
    accent:   'text-accent bg-accent/10 border-accent/20',
    critical: 'text-critical bg-critical/10 border-critical/20',
    high:     'text-high bg-high/10 border-high/20',
    medium:   'text-medium bg-medium/10 border-medium/20',
    low:      'text-low bg-low/10 border-low/20',
  }
  return (
    <div className="card flex items-center gap-4 animate-fade-in">
      <div className={`w-11 h-11 rounded-xl flex items-center justify-center border ${colorMap[color]}`}>
        <Icon size={20} />
      </div>
      <div>
        <p className="text-2xl font-display font-bold text-text">{value ?? '—'}</p>
        <p className="text-xs text-dim mt-0.5">{label}</p>
      </div>
    </div>
  )
}

export function Select({ value, onChange, options, className = '' }) {
  return (
    <select
      value={value}
      onChange={e => onChange(e.target.value)}
      className={`input ${className}`}
    >
      {options.map(o => (
        <option key={o.value} value={o.value}>{o.label}</option>
      ))}
    </select>
  )
}
