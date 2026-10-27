import { useEffect, useId, useRef, useState, type ReactNode } from 'react'
import { AlertTriangle } from 'lucide-react'

interface Props {
  open: boolean
  title: string
  message: string
  confirmLabel?: string
  danger?: boolean
  onConfirm: () => void
  onCancel: () => void
  children?: ReactNode
  requireTypedPhrase?: string
  width?: 'sm' | 'md'
}

export default function ConfirmDialog({
  open,
  title,
  message,
  confirmLabel = 'Confirm',
  danger = true,
  onConfirm,
  onCancel,
  children,
  requireTypedPhrase,
  width = 'sm',
}: Props) {
  const confirmRef = useRef<HTMLButtonElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  const [typed, setTyped] = useState('')
  const titleId = useId()
  const messageId = useId()

  useEffect(() => {
    if (!open) {
      setTyped('')
      return
    }
    if (requireTypedPhrase) {
      inputRef.current?.focus()
    } else {
      confirmRef.current?.focus()
    }
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onCancel()
    }
    document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [open, onCancel, requireTypedPhrase])

  if (!open) return null

  const tone = danger ? 'var(--danger)' : 'var(--accent)'
  const gated = requireTypedPhrase != null && typed !== requireTypedPhrase
  const widthClass = width === 'md' ? 'max-w-md' : 'max-w-sm'

  return (
    <>
      <div className="fixed inset-0 bg-black/50 z-[9998]" onClick={onCancel} />
      <div className="fixed inset-0 z-[9999] flex items-center justify-center p-4">
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby={titleId}
          aria-describedby={messageId}
          className={`bg-[var(--bg-secondary)] border border-[var(--border)] rounded-lg shadow-xl w-full ${widthClass}`}
        >
          <div className="px-5 pt-5 pb-3 flex items-start gap-3">
            <div
              className="rounded-full p-2 flex-shrink-0"
              style={{ background: `color-mix(in srgb, ${tone} 15%, transparent)` }}
            >
              <AlertTriangle size={20} style={{ color: tone }} />
            </div>
            <div className="min-w-0 flex-1">
              <h3 id={titleId} className="text-sm font-semibold text-[var(--text-primary)]">{title}</h3>
              <p id={messageId} className="text-sm text-[var(--text-secondary)] mt-1 leading-relaxed">{message}</p>
            </div>
          </div>
          {children != null && <div className="px-5 pb-2">{children}</div>}
          {requireTypedPhrase != null && (
            <div className="px-5 pb-2">
              <label className="block text-xs text-[var(--text-secondary)] mb-1">
                Type{' '}
                <span className="font-mono text-[var(--text-primary)]">{requireTypedPhrase}</span>{' '}
                to confirm
              </label>
              <input
                ref={inputRef}
                type="text"
                value={typed}
                onChange={(e) => setTyped(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !gated) onConfirm()
                }}
                autoComplete="off"
                autoCorrect="off"
                autoCapitalize="off"
                spellCheck={false}
                className="w-full px-2 py-1.5 text-sm font-mono bg-[var(--bg-primary)] border border-[var(--border)] rounded text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]"
                aria-label={`Type ${requireTypedPhrase} to confirm`}
              />
            </div>
          )}
          <div className="px-5 pb-4 pt-2 flex justify-end gap-2">
            <button
              onClick={onCancel}
              className="px-3 py-1.5 text-sm text-[var(--text-secondary)] hover:text-[var(--text-primary)] border border-[var(--border)] rounded"
            >
              Cancel
            </button>
            <button
              ref={confirmRef}
              onClick={onConfirm}
              disabled={gated}
              className="px-3 py-1.5 text-sm font-medium rounded disabled:opacity-40 disabled:cursor-not-allowed"
              style={{ background: tone, color: 'var(--bg-primary)' }}
            >
              {confirmLabel}
            </button>
          </div>
        </div>
      </div>
    </>
  )
}
