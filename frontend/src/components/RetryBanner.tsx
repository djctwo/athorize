import { AlertTriangle, RefreshCw } from 'lucide-react'

interface Props {
  title: string
  detail: string
  onRetry: () => void
  isPending?: boolean
  retryLabel?: string
}

export default function RetryBanner({
  title,
  detail,
  onRetry,
  isPending = false,
  retryLabel = 'Retry',
}: Props) {
  return (
    <div
      role="alert"
      className="border border-[var(--danger)]/50 bg-[var(--danger)]/10 px-4 py-3 mb-4 flex items-start gap-3"
    >
      <AlertTriangle
        size={16}
        className="flex-shrink-0 mt-0.5"
        style={{ color: 'var(--danger)' }}
      />
      <div className="flex-1 min-w-0">
        <div className="text-sm font-medium text-[var(--text-primary)]">{title}</div>
        <div className="text-xs text-[var(--text-secondary)] mt-0.5 break-words">
          {detail}
        </div>
      </div>
      <button
        type="button"
        onClick={onRetry}
        disabled={isPending}
        className="px-3 py-1.5 text-xs uppercase tracking-wider border border-[var(--danger)]/60 text-[var(--danger)] hover:bg-[var(--danger)]/15 inline-flex items-center gap-1.5 disabled:opacity-40 disabled:cursor-not-allowed flex-shrink-0"
      >
        <RefreshCw size={11} className={isPending ? 'animate-spin' : ''} />
        {isPending ? 'Retrying...' : retryLabel}
      </button>
    </div>
  )
}
