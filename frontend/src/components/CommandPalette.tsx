import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  LayoutDashboard, Server, AlertTriangle, FileCheck, Shield, Store,
  ClipboardCheck, CalendarDays, ScrollText, Settings, Crosshair,
  Activity, Boxes, Network, Radar, BookOpen, FileSpreadsheet, Search,
} from 'lucide-react'
import { api } from '../lib/api'

interface SearchResults {
  findings: { id: number; title: string; severity: string; status: string }[]
  systems: { id: number; name: string; acronym: string }[]
  evidence: { id: number; filename: string }[]
  risks: { id: number; title: string }[]
  advisories: { id: number; advisory_id: string; title: string }[]
  controls: { framework_id: string; control_id: string; title: string }[]
}

interface NavItem {
  label: string
  path: string
  icon: typeof LayoutDashboard
  keywords: string[]
}

const NAV_ITEMS: NavItem[] = [
  { label: 'Dashboard', path: '/', icon: LayoutDashboard, keywords: ['home', 'overview', 'summary'] },
  { label: 'Systems', path: '/systems', icon: Server, keywords: ['system', 'server', 'asset'] },
  { label: 'Findings', path: '/findings', icon: AlertTriangle, keywords: ['finding', 'poam', 'vulnerability', 'issue'] },
  { label: 'Evidence', path: '/evidence', icon: FileCheck, keywords: ['evidence', 'artifact', 'upload'] },
  { label: 'ConMon', path: '/conmon', icon: Activity, keywords: ['conmon', 'monitoring', 'continuous'] },
  { label: 'Assets', path: '/assets', icon: Boxes, keywords: ['asset', 'it', 'ot', 'hardware', 'software', 'scada', 'ics', 'plc', 'device', 'inventory'] },
  { label: 'Topology', path: '/topology', icon: Network, keywords: ['topology', 'network', 'map'] },
  { label: 'Advisories', path: '/advisories', icon: Radar, keywords: ['advisory', 'cisa', 'cve', 'ics'] },
  { label: 'Risk Register', path: '/risks', icon: BookOpen, keywords: ['risk', 'register', 'treatment'] },
  { label: 'Controls', path: '/controls', icon: Shield, keywords: ['control', 'requirement'] },
  { label: 'Frameworks', path: '/marketplace', icon: Store, keywords: ['framework', 'marketplace', 'activate'] },
  { label: 'Assessments', path: '/assessments', icon: ClipboardCheck, keywords: ['assessment', 'audit', 'test'] },
  { label: 'Calendar', path: '/calendar', icon: CalendarDays, keywords: ['calendar', 'deadline', 'schedule'] },
  { label: 'Reports', path: '/reports', icon: FileSpreadsheet, keywords: ['report', 'export', 'csv'] },
  { label: 'Red Team', path: '/red-team', icon: Crosshair, keywords: ['redteam', 'attack', 'chain', 'exposure'] },
  { label: 'Audit Log', path: '/audit', icon: ScrollText, keywords: ['audit', 'log', 'history', 'trail'] },
  { label: 'Settings', path: '/settings', icon: Settings, keywords: ['settings', 'config', 'preferences'] },
]

export function CommandPalette() {
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [selected, setSelected] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)
  const navigate = useNavigate()

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault()
        setOpen(prev => !prev)
        setQuery('')
        setSelected(0)
      }
    }
    document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [])

  useEffect(() => {
    if (open) inputRef.current?.focus()
  }, [open])

  // Debounce the content search so we don't hit the API per keystroke.
  const [debounced, setDebounced] = useState('')
  useEffect(() => {
    const t = setTimeout(() => setDebounced(query.trim()), 200)
    return () => clearTimeout(t)
  }, [query])

  const { data: content } = useQuery({
    queryKey: ['palette-search', debounced],
    queryFn: () => api.get<SearchResults>(`/search?q=${encodeURIComponent(debounced)}`),
    enabled: open && debounced.length >= 2,
    staleTime: 15_000,
  })

  const results = useMemo(() => {
    const q = query.trim().toLowerCase()
    const nav = (!q ? NAV_ITEMS : NAV_ITEMS.filter(item =>
      item.label.toLowerCase().includes(q) ||
      item.keywords.some(k => k.includes(q))
    )).map(item => ({ label: item.label, sublabel: '', icon: item.icon, path: item.path }))

    if (!content || q.length < 2) return nav
    const hits = [
      ...content.findings.map(f => ({
        label: f.title, sublabel: `Finding · ${f.severity} · ${f.status}`,
        icon: AlertTriangle, path: `/findings?focus=${f.id}`,
      })),
      ...content.systems.map(s => ({
        label: `${s.acronym} — ${s.name}`, sublabel: 'System', icon: Server, path: '/systems',
      })),
      ...content.controls.map(c => ({
        label: `${c.control_id} ${c.title}`, sublabel: `Control · ${c.framework_id}`,
        icon: Shield, path: `/controls?framework=${encodeURIComponent(c.framework_id)}`,
      })),
      ...content.evidence.map(e => ({
        label: e.filename, sublabel: 'Evidence', icon: FileCheck, path: '/evidence',
      })),
      ...content.risks.map(r => ({
        label: r.title, sublabel: 'Risk', icon: BookOpen, path: '/risks',
      })),
      ...content.advisories.map(a => ({
        label: `${a.advisory_id} — ${a.title}`, sublabel: 'Advisory', icon: Radar, path: '/advisories',
      })),
    ]
    return [...hits, ...nav]
  }, [query, content])

  const go = useCallback((path: string) => {
    navigate(path)
    setOpen(false)
    setQuery('')
  }, [navigate])

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setSelected(s => Math.min(s + 1, results.length - 1)) }
    if (e.key === 'ArrowUp') { e.preventDefault(); setSelected(s => Math.max(s - 1, 0)) }
    if (e.key === 'Enter' && results[selected]) { go(results[selected].path) }
    if (e.key === 'Escape') { setOpen(false) }
  }

  if (!open) return null

  return (
    <>
      <div className="fixed inset-0 bg-black/50 z-[60]" onClick={() => setOpen(false)} />
      <div className="fixed top-[15%] left-1/2 -translate-x-1/2 w-[480px] max-w-[calc(100vw-2rem)] bg-[var(--bg-secondary)] border border-[var(--border)] shadow-2xl z-[61]">
        <div className="flex items-center gap-2 px-4 py-3 border-b border-[var(--border)]">
          <Search size={16} className="text-[var(--text-secondary)]" />
          <input
            ref={inputRef}
            value={query}
            onChange={e => { setQuery(e.target.value); setSelected(0) }}
            onKeyDown={handleKeyDown}
            placeholder="Search pages, findings, controls, evidence…"
            className="flex-1 bg-transparent text-sm text-[var(--text-primary)] outline-none placeholder:text-[var(--text-secondary)]"
          />
          <kbd className="text-[10px] text-[var(--text-secondary)] border border-[var(--border)] px-1.5 py-0.5">ESC</kbd>
        </div>
        <div className="max-h-[360px] overflow-y-auto py-1">
          {results.length === 0 ? (
            <div className="px-4 py-6 text-center text-xs text-[var(--text-secondary)]">No results</div>
          ) : (
            results.map((item, i) => {
              const Icon = item.icon
              return (
                <button
                  key={`${item.path}:${item.label}`}
                  onClick={() => go(item.path)}
                  onMouseEnter={() => setSelected(i)}
                  className={`w-full flex items-center gap-3 px-4 py-2.5 text-sm text-left transition-colors ${
                    i === selected ? 'bg-[var(--accent)]/10 text-[var(--accent)]' : 'text-[var(--text-primary)] hover:bg-[var(--bg-tertiary)]'
                  }`}
                >
                  <Icon size={16} className="shrink-0" />
                  <span className="flex-1 min-w-0 truncate">{item.label}</span>
                  {item.sublabel && (
                    <span className="text-[10px] uppercase tracking-wider text-[var(--text-secondary)] shrink-0">{item.sublabel}</span>
                  )}
                </button>
              )
            })
          )}
        </div>
      </div>
    </>
  )
}
