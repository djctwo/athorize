import { CheckCircle, AlertCircle, Info, X } from 'lucide-react'
import { useToastStore, type ToastType } from '../store/toastStore'

const ICON: Record<ToastType, typeof CheckCircle> = {
  success: CheckCircle,
  error: AlertCircle,
  info: Info,
}
const TONE: Record<ToastType, string> = {
  success: 'var(--success)',
  error: 'var(--danger)',
  info: 'var(--info)',
}

export default function ToastContainer() {
  const toasts = useToastStore((s) => s.toasts)
  const dismiss = useToastStore((s) => s.dismiss)

  if (toasts.length === 0) return null

  return (
    <div className="fixed bottom-4 right-4 z-[9999] flex flex-col gap-2 max-w-sm" role="status" aria-live="polite" aria-atomic="false">
      {toasts.map((t) => {
        const Icon = ICON[t.type]
        return (
          <div
            key={t.id}
            className="flex items-start gap-2 px-3 py-2 bg-[var(--bg-tertiary)] border border-[var(--border)] shadow-lg animate-slide-up"
            style={{ borderLeftWidth: 3, borderLeftColor: TONE[t.type] }}
          >
            <Icon size={16} style={{ color: TONE[t.type], flexShrink: 0, marginTop: 2 }} />
            <span className="text-sm text-[var(--text-primary)] flex-1">{t.message}</span>
            {t.action && (
              <button
                onClick={() => {
                  t.action?.onAction()
                  dismiss(t.id)
                }}
                className="text-xs uppercase tracking-wider font-medium text-[var(--accent)] hover:text-[var(--text-primary)] shrink-0"
              >
                {t.action.label}
              </button>
            )}
            <button
              onClick={() => dismiss(t.id)}
              aria-label="Dismiss notification"
              className="text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
            >
              <X size={14} />
            </button>
          </div>
        )
      })}
    </div>
  )
}
