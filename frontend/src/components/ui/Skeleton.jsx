export function SkeletonRow({ cols = 6 }) {
  return (
    <tr className="border-b border-border/50">
      {Array.from({ length: cols }).map((_, i) => (
        <td key={i} className="px-4 py-3">
          <div className="h-4 bg-muted/60 rounded animate-pulse"
               style={{ width: `${60 + Math.random() * 30}%` }} />
        </td>
      ))}
    </tr>
  )
}

export function SkeletonCard() {
  return (
    <div className="card animate-pulse">
      <div className="flex items-center gap-4">
        <div className="w-11 h-11 rounded-xl bg-muted/60" />
        <div className="space-y-2 flex-1">
          <div className="h-6 bg-muted/60 rounded w-1/3" />
          <div className="h-3 bg-muted/40 rounded w-1/2" />
        </div>
      </div>
    </div>
  )
}

export function SkeletonChart() {
  return (
    <div className="card animate-pulse">
      <div className="h-4 bg-muted/60 rounded w-1/4 mb-4" />
      <div className="h-48 bg-muted/30 rounded-lg" />
    </div>
  )
}

export function SkeletonTable({ rows = 8, cols = 6 }) {
  return (
    <div className="card p-0 overflow-hidden">
      <div className="bg-surface/60 px-4 py-3 border-b border-border flex gap-4">
        {Array.from({ length: cols }).map((_, i) => (
          <div key={i} className="h-3 bg-muted/60 rounded animate-pulse"
               style={{ width: `${40 + Math.random() * 40}px` }} />
        ))}
      </div>
      <table className="w-full">
        <tbody>
          {Array.from({ length: rows }).map((_, i) => (
            <SkeletonRow key={i} cols={cols} />
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function SkeletonHostCard() {
  return (
    <div className="card animate-pulse">
      <div className="flex items-center gap-3 mb-4">
        <div className="w-9 h-9 rounded-xl bg-muted/60" />
        <div className="space-y-2 flex-1">
          <div className="h-4 bg-muted/60 rounded w-1/2" />
          <div className="h-3 bg-muted/40 rounded w-1/3" />
        </div>
      </div>
      <div className="grid grid-cols-3 gap-3">
        {[1,2,3].map(i => (
          <div key={i} className="h-14 bg-muted/40 rounded-lg" />
        ))}
      </div>
    </div>
  )
}
