import { ChevronUp, ChevronDown, ChevronsUpDown } from 'lucide-react'
import type { SortDir } from '../lib/useSort'

interface Props {
  label: string
  field: string
  active: boolean
  dir: SortDir
  onSort: () => void
}

export default function SortHeader({ label, active, dir, onSort }: Props) {
  return (
    <th
      onClick={onSort}
      onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSort() }}}
      tabIndex={0}
      role="button"
      aria-label={`Sort by ${label}${active ? (dir === 'asc' ? ', ascending' : ', descending') : ''}`}
      className="text-left px-3 py-2 border-b border-[var(--border)] cursor-pointer select-none hover:text-[var(--accent)] transition-colors focus:outline-none focus:text-[var(--accent)]"
    >
      <span className="inline-flex items-center gap-1">
        {label}
        {active ? (
          dir === 'asc' ? (
            <ChevronUp size={12} />
          ) : (
            <ChevronDown size={12} />
          )
        ) : (
          <ChevronsUpDown size={10} className="opacity-30" />
        )}
      </span>
    </th>
  )
}
