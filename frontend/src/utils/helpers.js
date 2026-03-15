export const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 }

export function severityClass(s) {
  return {
    critical: 'severity-critical',
    high:     'severity-high',
    medium:   'severity-medium',
    low:      'severity-low',
  }[s] ?? 'text-dim bg-muted border border-border'
}

export function statusClass(s) {
  return {
    open:          'status-open',
    investigating: 'status-investigating',
    resolved:      'status-resolved',
  }[s] ?? 'text-dim bg-muted border border-border'
}

export function severityColor(s) {
  return {
    critical: '#ef4444',
    high:     '#f97316',
    medium:   '#eab308',
    low:      '#22c55e',
  }[s] ?? '#4a5578'
}

export function formatTime(iso) {
  if (!iso) return '—'
  // Append 'Z' so JS knows this is UTC, then convert to browser local time
  return new Date(iso + 'Z').toLocaleString('en-GB', {
    day:    '2-digit',
    month:  'short',
    hour:   '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

export function formatEventType(t) {
  return t?.replace(/_/g, ' ') ?? '—'
}

export function timeAgo(iso) {
  const diff = Date.now() - new Date(iso + 'Z').getTime()
  const s = Math.floor(diff / 1000)
  if (s < 60)    return `${s}s ago`
  if (s < 3600)  return `${Math.floor(s/60)}m ago`
  if (s < 86400) return `${Math.floor(s/3600)}h ago`
  return `${Math.floor(s/86400)}d ago`
}