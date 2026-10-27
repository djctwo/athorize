import { useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'

export type SortDir = 'asc' | 'desc'

export interface SortState<K extends string> {
  key: K
  dir: SortDir
}

export function useSort<K extends string>(defaultKey: K, defaultDir: SortDir = 'asc') {
  const [sort, setSort] = useState<SortState<K>>({ key: defaultKey, dir: defaultDir })

  const toggle = (key: K) => {
    setSort((s) =>
      s.key === key
        ? { key, dir: s.dir === 'asc' ? 'desc' : 'asc' }
        : { key, dir: 'asc' }
    )
  }

  return { sort, toggle }
}

export function sorted<T>(items: T[], key: string, dir: SortDir): T[] {
  return [...items].sort((a, b) => {
    const av = (a as Record<string, unknown>)[key]
    const bv = (b as Record<string, unknown>)[key]
    if (av == null && bv == null) return 0
    if (av == null) return 1
    if (bv == null) return -1
    if (typeof av === 'number' && typeof bv === 'number')
      return dir === 'asc' ? av - bv : bv - av
    const as = String(av).toLowerCase()
    const bs = String(bv).toLowerCase()
    const cmp = as < bs ? -1 : as > bs ? 1 : 0
    return dir === 'asc' ? cmp : -cmp
  })
}

export function useSorted<T, K extends string>(
  items: T[],
  defaultKey: K,
  defaultDir: SortDir = 'asc'
) {
  const { sort, toggle } = useSort(defaultKey, defaultDir)
  const data = useMemo(() => sorted(items, sort.key, sort.dir), [items, sort.key, sort.dir])
  return { data, sort, toggle }
}

export function useUrlSort<K extends string>(
  defaultKey: K,
  defaultDir: SortDir = 'asc',
  paramPrefix?: string
) {
  const [params, setParams] = useSearchParams()
  const sortParam = paramPrefix ? `${paramPrefix}_sort` : 'sort'
  const dirParam = paramPrefix ? `${paramPrefix}_dir` : 'dir'
  const rawDir = params.get(dirParam)
  const dir: SortDir = rawDir === 'asc' || rawDir === 'desc' ? rawDir : defaultDir
  const key = (params.get(sortParam) as K) || defaultKey
  const sort: SortState<K> = { key, dir }

  const toggle = (k: K) => {
    const next: SortState<K> =
      sort.key === k
        ? { key: k, dir: sort.dir === 'asc' ? 'desc' : 'asc' }
        : { key: k, dir: 'asc' }
    const np = new URLSearchParams(params)
    np.set(sortParam, next.key)
    np.set(dirParam, next.dir)
    setParams(np, { replace: true })
  }

  return { sort, toggle }
}

export function useUrlSorted<T, K extends string>(
  items: T[],
  defaultKey: K,
  defaultDir: SortDir = 'asc',
  paramPrefix?: string
) {
  const { sort, toggle } = useUrlSort(defaultKey, defaultDir, paramPrefix)
  const data = useMemo(() => sorted(items, sort.key, sort.dir), [items, sort.key, sort.dir])
  return { data, sort, toggle }
}
