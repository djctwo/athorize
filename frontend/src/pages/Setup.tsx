import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { DEMO_LOGINS } from '../lib/demo'

export default function Setup() {
  const [orgName, setOrgName] = useState('')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [email, setEmail] = useState('')
  const [setupToken, setSetupToken] = useState('')
  const [error, setError] = useState('')
  const queryClient = useQueryClient()

  const { data: status } = useQuery({
    queryKey: ['auth-status'],
    queryFn: () => api.get<{ setup_complete: boolean; setup_token_required: boolean }>('/auth/status'),
  })
  const tokenRequired = status?.setup_token_required === true

  const signedIn = () => {
    queryClient.invalidateQueries({ queryKey: ['auth-status'] })
    queryClient.invalidateQueries({ queryKey: ['me'] })
    queryClient.invalidateQueries({ queryKey: ['me-effect'] })
  }

  const setup = useMutation({
    mutationFn: () => api.post('/auth/setup', {
      org_name: orgName,
      username,
      password,
      email,
      display_name: username,
      setup_token: setupToken,
    }),
    onSuccess: signedIn,
    onError: (err: Error) => setError(err.message),
  })

  // First-run alternative: load the sample companies and sign in as the demo
  // admin (POST /auth/setup/demo — same one-time token, empty instance only).
  const demo = useMutation({
    mutationFn: () => api.post('/auth/setup/demo', { setup_token: setupToken }),
    onSuccess: signedIn,
    onError: (err: Error) => setError(err.message),
  })
  const busy = setup.isPending || demo.isPending

  return (
    <div className="flex items-center justify-center min-h-screen py-8">
      <div className="w-[480px] max-w-[calc(100vw-2rem)] bg-bg-secondary border border-border p-8">
        <h1 className="text-2xl font-bold text-accent mb-1">Athorize</h1>
        <p className="text-text-muted text-sm mb-6">Set up your organization</p>

        {error && <div role="alert" className="text-danger text-sm mb-4 p-2 bg-danger/10 border border-danger/20">{error}</div>}

        {tokenRequired && (
          <>
            <label className="block text-sm text-text-secondary mb-1" htmlFor="setup-token">Setup Token</label>
            <input id="setup-token" className="w-full mb-1" value={setupToken} onChange={(e) => setSetupToken(e.target.value)} placeholder="Paste the token from the server log or <data dir>/setup-token" autoFocus />
            <p className="text-[11px] text-text-muted mb-5">
              A one-time code that proves you run this server. Find it in the server log (the desktop app's
              console window; <code>docker compose logs</code> for Docker) or in the file <code>setup-token</code> in
              the data folder. Both choices below need it.
            </p>
          </>
        )}

        <form onSubmit={(e) => { e.preventDefault(); setError(''); setup.mutate() }}>
          <h2 className="text-sm font-semibold text-text-primary mb-3">Set up my company</h2>

          <label className="block text-sm text-text-secondary mb-1" htmlFor="setup-org">Organization Name</label>
          <input id="setup-org" className="w-full mb-4" value={orgName} onChange={(e) => setOrgName(e.target.value)} placeholder="Your Company" autoFocus={!tokenRequired} />

          <label className="block text-sm text-text-secondary mb-1" htmlFor="setup-username">Admin Username</label>
          <input id="setup-username" className="w-full mb-4" value={username} onChange={(e) => setUsername(e.target.value)} placeholder="admin" />

          <label className="block text-sm text-text-secondary mb-1" htmlFor="setup-email">Email</label>
          <input id="setup-email" className="w-full mb-4" type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@company.com" />

          <label className="block text-sm text-text-secondary mb-1" htmlFor="setup-password">Password</label>
          <input id="setup-password" className="w-full mb-1" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
          <p className="text-[11px] text-text-muted mb-6">
            At least 12 characters, with three of: lowercase, uppercase, digit, symbol. Not a common password or your username.
          </p>

          <button
            type="submit"
            disabled={busy}
            className="w-full py-2 bg-accent hover:bg-accent-hover text-white font-medium transition-colors disabled:opacity-50"
          >
            {setup.isPending ? 'Setting up...' : 'Create Organization'}
          </button>
        </form>

        <div className="flex items-center gap-3 my-6" aria-hidden="true">
          <div className="flex-1 h-px bg-border" />
          <span className="text-xs text-text-muted">or</span>
          <div className="flex-1 h-px bg-border" />
        </div>

        <section aria-labelledby="setup-demo-heading">
          <h2 id="setup-demo-heading" className="text-sm font-semibold text-text-primary mb-2">Just want to look around?</h2>
          <p className="text-xs text-text-muted mb-2">
            Load three sample companies (Acme, Northwind, Contoso) with systems, findings and evidence. You are signed
            in as <strong>admin</strong>. Every demo account's password is the username:
          </p>
          <p className="text-xs text-text-secondary mb-2 font-mono break-words">{DEMO_LOGINS.join(', ')}</p>
          <p className="text-xs text-text-muted mb-4">
            These passwords are public, so explore only where others cannot reach this server. When you are ready
            for real use, an admin can delete all of it in Settings → Start fresh, which brings you back to this
            screen.
          </p>
          <button
            type="button"
            disabled={busy}
            onClick={() => { setError(''); demo.mutate() }}
            className="w-full py-2 border border-border hover:border-accent text-text-secondary hover:text-text-primary font-medium transition-colors disabled:opacity-50"
          >
            {demo.isPending ? 'Loading demo data…' : 'Explore with demo data'}
          </button>
        </section>
      </div>
    </div>
  )
}
