import { useCallback, useEffect, useState } from 'react'

// Rows can be keyed by a numeric PK (findings) or a string key (controls,
// keyed by control_id). The id type is derived from T so existing
// useBulkSelect<Finding> call sites keep their Set<number> API unchanged.
export interface BulkSelectApi<T extends { id: string | number }> {
  selectedIds: Set<T['id']>
  isSelected: (id: T['id']) => boolean
  toggleOne: (id: T['id']) => void
  toggleAll: (ids: T['id'][], checked: boolean) => void
  clear: () => void
  selectedCount: number
  someSelected: (ids: T['id'][]) => boolean
  allSelected: (ids: T['id'][]) => boolean
  selectedItems: (items: T[]) => T[]
}

export function useBulkSelect<T extends { id: string | number }>(
  resetKey: unknown,
): BulkSelectApi<T> {
  const [selectedIds, setSelectedIds] = useState<Set<T['id']>>(new Set())

  useEffect(() => {
    setSelectedIds(new Set())
  }, [resetKey])

  const isSelected = useCallback(
    (id: T['id']) => selectedIds.has(id),
    [selectedIds],
  )

  const toggleOne = useCallback((id: T['id']) => {
    setSelectedIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }, [])

  const toggleAll = useCallback((ids: T['id'][], checked: boolean) => {
    setSelectedIds((prev) => {
      const next = new Set(prev)
      if (checked) ids.forEach((id) => next.add(id))
      else ids.forEach((id) => next.delete(id))
      return next
    })
  }, [])

  const clear = useCallback(() => setSelectedIds(new Set()), [])

  const someSelected = useCallback(
    (ids: T['id'][]) => {
      if (ids.length === 0) return false
      const every = ids.every((id) => selectedIds.has(id))
      return ids.some((id) => selectedIds.has(id)) && !every
    },
    [selectedIds],
  )

  const allSelected = useCallback(
    (ids: T['id'][]) => ids.length > 0 && ids.every((id) => selectedIds.has(id)),
    [selectedIds],
  )

  const selectedItems = useCallback(
    (items: T[]) => items.filter((it) => selectedIds.has(it.id)),
    [selectedIds],
  )

  return {
    selectedIds,
    isSelected,
    toggleOne,
    toggleAll,
    clear,
    selectedCount: selectedIds.size,
    someSelected,
    allSelected,
    selectedItems,
  }
}
