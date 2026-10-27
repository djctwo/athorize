import { X } from 'lucide-react'
import { useEffect, useRef, type ReactNode } from 'react'

interface Props {
  open: boolean
  onClose: () => void
  width?: number
  eyebrow?: ReactNode
  title: ReactNode
  subtitle?: ReactNode
  headerAccessory?: ReactNode
  topBar?: ReactNode
  footer?: ReactNode
  bodyClassName?: string
  children: ReactNode
}

export function SlideInPanel({
  open,
  onClose,
  width = 520,
  eyebrow,
  title,
  subtitle,
  headerAccessory,
  topBar,
  footer,
  bodyClassName = 'flex-1 overflow-y-auto px-5 py-3',
  children,
}: Props) {
  const panelRef = useRef<HTMLElement>(null)

  useEffect(() => {
    if (!open) return
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
      if (e.key === 'Tab' && panelRef.current) {
        const focusable = panelRef.current.querySelectorAll<HTMLElement>(
          'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
        )
        if (focusable.length === 0) return
        const first = focusable[0]
        const last = focusable[focusable.length - 1]
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault()
          last.focus()
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault()
          first.focus()
        }
      }
    }
    document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [open, onClose])

  useEffect(() => {
    if (open && panelRef.current) {
      const first = panelRef.current.querySelector<HTMLElement>(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
      )
      first?.focus()
    }
  }, [open])

  if (!open) return null
  return (
    <>
      <div className="fixed inset-0 bg-black/40 z-40" onClick={onClose} />
      <aside
        ref={panelRef}
        className="fixed top-0 right-0 h-screen bg-[var(--bg-secondary)] border-l border-[var(--border)] z-50 flex flex-col"
        // Never wider than the viewport: at phone width a 520/580px panel opened
        // with its left edge (title, labels, inputs) off-screen (R2USER-3).
        style={{ width: `min(${width}px, 100vw)` }}
      >
        <div className="px-5 py-4 border-b border-[var(--border)] flex items-start justify-between gap-3">
          <div className="min-w-0">
            {eyebrow && (
              <div className="text-[11px] uppercase tracking-wider text-[var(--text-secondary)]">
                {eyebrow}
              </div>
            )}
            <h2 className="text-base text-[var(--text-primary)] mt-1 leading-snug">
              {title}
            </h2>
            {subtitle && (
              <div className="text-xs text-[var(--text-secondary)] mt-1">
                {subtitle}
              </div>
            )}
            {headerAccessory && <div className="mt-2">{headerAccessory}</div>}
          </div>
          <button
            onClick={onClose}
            className="text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
            aria-label="Close"
          >
            <X size={18} />
          </button>
        </div>
        {topBar}
        <div className={bodyClassName}>{children}</div>
        {footer && (
          <div className="border-t border-[var(--border)] px-5 py-3 flex items-center gap-2">
            {footer}
          </div>
        )}
      </aside>
    </>
  )
}
