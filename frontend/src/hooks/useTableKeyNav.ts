import { useCallback, useEffect, useRef, useState } from 'react'

type Options<T extends { id: number }> = {
  rows: T[]
  enabled?: boolean
  onOpen?: (row: T) => void
  onToggleSelect?: (row: T) => void
}

export function useTableKeyNav<T extends { id: number }>({
  rows,
  enabled = true,
  onOpen,
  onToggleSelect,
}: Options<T>) {
  const [activeId, setActiveId] = useState<number | null>(null)
  const rowRefs = useRef<Map<number, HTMLElement>>(new Map())

  const registerRow = useCallback((id: number, el: HTMLElement | null) => {
    const map = rowRefs.current
    if (el) map.set(id, el)
    else map.delete(id)
  }, [])

  useEffect(() => {
    if (activeId != null && !rows.some((r) => r.id === activeId)) {
      setActiveId(null)
    }
  }, [rows, activeId])

  useEffect(() => {
    if (!enabled) return
    function onShortcut(e: Event) {
      const detail = (e as CustomEvent).detail as { key?: string } | undefined
      const key = detail?.key
      if (key !== 'j' && key !== 'k' && key !== 'x' && key !== 'Enter') return
      if (rows.length === 0) return

      if (key === 'j' || key === 'k') {
        setActiveId((prev) => {
          const idx = prev == null ? -1 : rows.findIndex((r) => r.id === prev)
          const nextIdx =
            key === 'j'
              ? Math.min(rows.length - 1, idx + 1)
              : idx <= 0
              ? 0
              : idx - 1
          const next = rows[nextIdx]
          if (next) {
            requestAnimationFrame(() => {
              const el = rowRefs.current.get(next.id)
              if (el) {
                el.focus({ preventScroll: true })
                el.scrollIntoView({ block: 'nearest', behavior: 'smooth' })
              }
            })
          }
          return next ? next.id : prev
        })
        return
      }

      if (key === 'x') {
        if (activeId == null) return
        const row = rows.find((r) => r.id === activeId)
        if (row && onToggleSelect) onToggleSelect(row)
        return
      }

      if (key === 'Enter') {
        if (activeId == null) return
        const row = rows.find((r) => r.id === activeId)
        if (row && onOpen) onOpen(row)
        return
      }
    }
    window.addEventListener('universal:shortcut', onShortcut)
    return () => window.removeEventListener('universal:shortcut', onShortcut)
  }, [rows, activeId, enabled, onOpen, onToggleSelect])

  return {
    activeId,
    setActiveId,
    registerRow,
  }
}
