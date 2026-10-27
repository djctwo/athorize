export function SkeletonBar({ className = '', style }: { className?: string; style?: React.CSSProperties }) {
  return (
    <div
      className={`bg-[var(--border)] animate-pulse-bg ${className}`}
      style={style}
      aria-hidden="true"
    />
  )
}

export function SkeletonMetrics({ count = 4 }: { count?: number }) {
  return (
    <div className="flex border border-[var(--border)] bg-[var(--bg-secondary)]">
      {Array.from({ length: count }).map((_, i) => (
        <div
          key={i}
          className="flex-1 px-4 py-3 border-r border-[var(--border)] last:border-r-0"
        >
          <SkeletonBar className="h-3 w-16 mb-2" />
          <SkeletonBar className="h-6 w-10" />
        </div>
      ))}
    </div>
  )
}

export function SkeletonTable({ rows = 6, cols = 5 }: { rows?: number; cols?: number }) {
  return (
    <div className="border border-[var(--border)] bg-[var(--bg-secondary)]">
      <div className="flex gap-4 px-3 py-2 border-b border-[var(--border)]">
        {Array.from({ length: cols }).map((_, i) => (
          <SkeletonBar key={i} className="h-3 flex-1 max-w-[120px]" />
        ))}
      </div>
      {Array.from({ length: rows }).map((_, r) => (
        <div key={r} className="flex gap-4 px-3 py-3 border-b border-[var(--border)] last:border-b-0">
          {Array.from({ length: cols }).map((_, c) => (
            <SkeletonBar
              key={c}
              className="h-3.5 flex-1"
              style={{ maxWidth: c === 0 ? 80 : c === 1 ? 200 : 100 }}
            />
          ))}
        </div>
      ))}
    </div>
  )
}

export function SkeletonCards({ count = 3 }: { count?: number }) {
  return (
    <div className="grid grid-cols-3 gap-4 p-4">
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="border border-[var(--border)] bg-[var(--bg-secondary)] p-4 space-y-3">
          <SkeletonBar className="h-4 w-3/4" />
          <SkeletonBar className="h-3 w-1/2" />
          <div className="flex gap-2 mt-2">
            <SkeletonBar className="h-5 w-16" />
            <SkeletonBar className="h-5 w-16" />
          </div>
          <SkeletonBar className="h-3 w-full mt-3" />
          <SkeletonBar className="h-3 w-2/3" />
        </div>
      ))}
    </div>
  )
}

export function SkeletonPage({
  metrics = 4,
  variant = 'table',
}: {
  metrics?: number
  variant?: 'table' | 'cards'
}) {
  return (
    <div className="p-4 space-y-4" aria-busy="true" aria-label="Loading page content">
      <div className="flex items-center justify-between">
        <SkeletonBar className="h-6 w-48" />
        <div className="flex gap-2">
          <SkeletonBar className="h-8 w-24" />
          <SkeletonBar className="h-8 w-24" />
        </div>
      </div>
      <SkeletonMetrics count={metrics} />
      {variant === 'table' && <SkeletonTable />}
      {variant === 'cards' && <SkeletonCards />}
    </div>
  )
}
