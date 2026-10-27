import { useEffect, useState } from 'react'
import { NavLink, useLocation, useNavigate } from 'react-router-dom'
import { useUserStore } from '../store/userStore'
import { useNavStore } from '../store/navStore'
import { api } from '../lib/api'
import { DEMO_LOGINS } from '../lib/demo'
import OrgSwitcher from './OrgSwitcher'
import {
  ArrowLeftRight, LayoutDashboard, Server, AlertTriangle, FileCheck, Shield,
  Store, ClipboardCheck, CalendarDays, ScrollText, Settings, LogOut, Crosshair,
  Activity, Network, Radar, BookOpen, FileSpreadsheet, HelpCircle, Users, Boxes,
  ChevronDown, Briefcase, DatabaseZap, Menu, X, TriangleAlert,
} from 'lucide-react'

type NavItem = { to: string; icon: typeof Server; label: string }
type NavGroup = { title: string; items: NavItem[] }

const navGroups: NavGroup[] = [
  {
    title: 'Overview',
    items: [
      { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
    ],
  },
  {
    title: 'Compliance',
    items: [
      { to: '/marketplace', icon: Store, label: 'Frameworks' },
      { to: '/controls', icon: Shield, label: 'Controls' },
      { to: '/crosswalk', icon: ArrowLeftRight, label: 'Crosswalk' },
      { to: '/findings', icon: AlertTriangle, label: 'Findings' },
      { to: '/evidence', icon: FileCheck, label: 'Evidence' },
      { to: '/assessments', icon: ClipboardCheck, label: 'Assessments' },
      { to: '/inspection', icon: ClipboardCheck, label: 'Inspection Prep' },
    ],
  },
  {
    title: 'Operations',
    items: [
      { to: '/conmon', icon: Activity, label: 'ConMon' },
      { to: '/advisories', icon: Radar, label: 'Advisories' },
      { to: '/red-team', icon: Crosshair, label: 'Red Team' },
      { to: '/risks', icon: BookOpen, label: 'Risk Register' },
      { to: '/calendar', icon: CalendarDays, label: 'Calendar' },
    ],
  },
  {
    title: 'Inventory',
    items: [
      { to: '/systems', icon: Server, label: 'Systems' },
      { to: '/assets', icon: Boxes, label: 'Assets' },
      { to: '/topology', icon: Network, label: 'Topology' },
    ],
  },
  {
    title: 'Admin',
    items: [
      { to: '/reports', icon: FileSpreadsheet, label: 'Reports' },
      { to: '/migration', icon: DatabaseZap, label: 'Migration' },
      { to: '/users', icon: Users, label: 'Users' },
      { to: '/audit', icon: ScrollText, label: 'Audit Log' },
      { to: '/settings', icon: Settings, label: 'Settings' },
      { to: '/help', icon: HelpCircle, label: 'Help' },
    ],
  },
]

export default function Layout({ children }: { children: React.ReactNode }) {
  const { user, setUser } = useUserStore()
  const { collapsed, toggleGroup } = useNavStore()
  const navigate = useNavigate()
  const location = useLocation()
  // Below md the sidebar is an off-canvas drawer (E2E-19); it closes on navigation.
  const [navOpen, setNavOpen] = useState(false)
  useEffect(() => { setNavOpen(false) }, [location.pathname])

  // Operators get the cross-company Portfolio view in Overview.
  const groups: NavGroup[] = user?.is_operator
    ? navGroups.map(g => g.title === 'Overview'
        ? { ...g, items: [...g.items, { to: '/portfolio', icon: Briefcase, label: 'Portfolio' }] }
        : g)
    : navGroups

  const handleLogout = async () => {
    await api.post('/auth/logout')
    setUser(null)
    navigate('/')
  }

  return (
    <div className="flex h-screen">
      {navOpen && (
        <div className="fixed inset-0 bg-black/50 z-40 md:hidden" onClick={() => setNavOpen(false)} aria-hidden="true" />
      )}
      <aside
        id="app-sidebar"
        className={`fixed inset-y-0 left-0 z-50 w-56 bg-bg-secondary border-r border-border flex flex-col transition-transform md:static md:z-auto md:translate-x-0 ${
          navOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <div className="px-4 py-3 border-b border-border relative">
          <button
            onClick={() => setNavOpen(false)}
            className="md:hidden absolute right-3 top-3 text-text-muted hover:text-text-primary"
            aria-label="Close menu"
          >
            <X size={18} />
          </button>
          <h1 className="text-lg font-bold text-accent">Athorize</h1>
          <p className="text-xs text-text-muted">Compliance Operations</p>
          <OrgSwitcher />
        </div>

        <nav className="flex-1 py-2 overflow-y-auto">
          {groups.map(({ title, items }) => {
            const isCollapsed = collapsed[title]
            return (
              <div key={title} className="mb-1">
                <button
                  onClick={() => toggleGroup(title)}
                  className="w-full flex items-center justify-between px-4 py-1 text-[10px] font-semibold uppercase tracking-wider text-text-muted hover:text-text-secondary transition-colors"
                  aria-expanded={!isCollapsed}
                >
                  <span>{title}</span>
                  <ChevronDown
                    size={12}
                    className={`transition-transform ${isCollapsed ? '-rotate-90' : ''}`}
                  />
                </button>
                {!isCollapsed && items.map(({ to, icon: Icon, label }) => (
                  <NavLink
                    key={to}
                    to={to}
                    end={to === '/'}
                    className={({ isActive }) =>
                      `flex items-center gap-3 px-4 py-[5px] text-sm transition-colors ${
                        isActive
                          ? 'text-accent bg-bg-tertiary border-r-2 border-accent'
                          : 'text-text-secondary hover:text-text-primary hover:bg-bg-tertiary'
                      }`
                    }
                  >
                    <Icon size={16} />
                    {label}
                  </NavLink>
                ))}
              </div>
            )
          })}
        </nav>

        <div className="px-4 py-3 border-t border-border">
          <div className="flex items-center justify-between">
            <div className="text-sm">
              <div className="text-text-primary font-medium">{user?.display_name}</div>
              <div className="text-xs text-text-muted capitalize">{user?.role?.replace('_', ' ')}</div>
            </div>
            <button onClick={handleLogout} className="text-text-muted hover:text-danger" title="Logout" aria-label="Log out">
              <LogOut size={16} />
            </button>
          </div>
        </div>
      </aside>

      <div className="flex-1 min-w-0 flex flex-col">
        <header className="md:hidden flex items-center gap-3 px-4 py-2 border-b border-border bg-bg-secondary">
          <button
            onClick={() => setNavOpen(true)}
            className="text-text-secondary hover:text-text-primary"
            aria-label="Open menu"
            aria-controls="app-sidebar"
            aria-expanded={navOpen}
          >
            <Menu size={20} />
          </button>
          <span className="text-base font-bold text-accent">Athorize</span>
        </header>
        {user?.demo_instance && (
          <div
            role="note"
            className="flex items-start gap-2 px-4 md:px-6 py-2 text-xs border-b border-warning/30 bg-warning/10 text-text-primary"
          >
            <TriangleAlert size={14} className="text-warning flex-shrink-0 mt-0.5" />
            <span>
              <strong className="font-semibold">Demo instance</strong> — sample data and publicly known default
              passwords (each demo account's password is its username: {DEMO_LOGINS.join(', ')}). Don't store real
              data here; {user.demo_autoseed
                ? 'for real use, install without the demo seed.'
                : 'when you are ready for real use, an admin can delete all of it in Settings → Start fresh.'}
            </span>
          </div>
        )}
        <main className="flex-1 min-w-0 overflow-y-auto p-4 md:p-6">
          {children}
        </main>
      </div>
    </div>
  )
}
