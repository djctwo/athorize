import { Routes, Route, Navigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { api } from './lib/api'
import { useUserStore } from './store/userStore'
import type { User } from './types'
import Layout from './components/Layout'
import ToastContainer from './components/ToastContainer'
import ErrorBoundary from './components/ErrorBoundary'
import { CommandPalette } from './components/CommandPalette'
import Login from './pages/Login'
import Setup from './pages/Setup'
import Dashboard from './pages/Dashboard'
import Portfolio from './pages/Portfolio'
import FrameworkBuilder from './pages/FrameworkBuilder'
import Migration from './pages/Migration'
import Systems from './pages/Systems'
import Findings from './pages/Findings'
import Evidence from './pages/Evidence'
import Controls from './pages/Controls'
import CrosswalkReview from './pages/CrosswalkReview'
import InspectionPrep from './pages/InspectionPrep'
import Marketplace from './pages/Marketplace'
import Assessments from './pages/Assessments'
import Calendar from './pages/Calendar'
import AuditLog from './pages/AuditLog'
import Settings from './pages/Settings'
import RedTeam from './pages/RedTeam'
import ConMon from './pages/ConMon'
import Assets from './pages/Assets'
import ITAssets from './pages/ITAssets'
import OTAssets from './pages/OTAssets'
import Topology from './pages/Topology'
import Advisories from './pages/Advisories'
import RiskRegister from './pages/RiskRegister'
import Reports from './pages/Reports'
import Help from './pages/Help'
import Users from './pages/Users'

function App() {
  const { user, setUser } = useUserStore()

  const { data: status, isLoading: statusLoading } = useQuery({
    queryKey: ['auth-status'],
    queryFn: () => api.get<{ setup_complete: boolean }>('/auth/status'),
  })

  const { isLoading: meLoading } = useQuery({
    queryKey: ['me'],
    queryFn: () => api.get<User>('/auth/me'),
    enabled: status?.setup_complete === true,
    retry: false,
    meta: { onSuccess: setUser },
  })

  useQuery({
    queryKey: ['me-effect'],
    queryFn: async () => {
      if (status?.setup_complete) {
        try {
          const u = await api.get<User>('/auth/me')
          setUser(u)
        } catch {
          setUser(null)
        }
      }
      return null
    },
    enabled: status?.setup_complete === true && !user,
  })

  if (statusLoading || meLoading) {
    return <div className="flex items-center justify-center h-screen text-text-secondary">Loading...</div>
  }

  if (!status?.setup_complete) {
    return <Setup />
  }

  if (!user) {
    return <Login />
  }

  return (
    <ErrorBoundary>
      <Layout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/portfolio" element={<Portfolio />} />
          <Route path="/framework-builder" element={<FrameworkBuilder />} />
          <Route path="/migration" element={<Migration />} />
          <Route path="/systems" element={<Systems />} />
          <Route path="/findings" element={<Findings />} />
          <Route path="/evidence" element={<Evidence />} />
          <Route path="/controls" element={<Controls />} />
          <Route path="/crosswalk" element={<CrosswalkReview />} />
          <Route path="/inspection" element={<InspectionPrep />} />
          <Route path="/marketplace" element={<Marketplace />} />
          <Route path="/assessments" element={<Assessments />} />
          <Route path="/calendar" element={<Calendar />} />
          <Route path="/conmon" element={<ConMon />} />
          <Route path="/assets" element={<Assets />} />
          {/* legacy routes kept for back-compat deep links; nav now points to /assets */}
          <Route path="/it-assets" element={<ITAssets />} />
          <Route path="/ot-assets" element={<OTAssets />} />
          <Route path="/topology" element={<Topology />} />
          <Route path="/advisories" element={<Advisories />} />
          <Route path="/risks" element={<RiskRegister />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/red-team" element={<RedTeam />} />
          <Route path="/audit" element={<AuditLog />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/help" element={<Help />} />
          <Route path="/users" element={<Users />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Layout>
      <ToastContainer />
      <CommandPalette />
    </ErrorBoundary>
  )
}

export default App
