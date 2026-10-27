import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'

export default function Login() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const queryClient = useQueryClient()

  const { data: status } = useQuery({
    queryKey: ['auth-status'],
    queryFn: () => api.get<{ oidc_enabled?: boolean }>('/auth/status'),
  })

  const login = useMutation({
    mutationFn: () => api.post('/auth/login', { username, password }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['me'] })
      queryClient.invalidateQueries({ queryKey: ['me-effect'] })
    },
    onError: (err: Error) => setError(err.message),
  })

  return (
    <div className="flex items-center justify-center h-screen">
      <div className="w-96 max-w-[calc(100vw-2rem)] bg-bg-secondary border border-border p-8">
        <h1 className="text-2xl font-bold text-accent mb-1">Athorize</h1>
        <p className="text-text-muted text-sm mb-6">Compliance Operations Platform</p>

        {error && <div role="alert" className="text-danger text-sm mb-4 p-2 bg-danger/10 border border-danger/20">{error}</div>}

        <form onSubmit={(e) => { e.preventDefault(); login.mutate() }}>
          <label className="block text-sm text-text-secondary mb-1" htmlFor="login-username">Username</label>
          <input id="login-username" autoComplete="username" className="w-full mb-4" value={username} onChange={(e) => setUsername(e.target.value)} autoFocus />

          <label className="block text-sm text-text-secondary mb-1" htmlFor="login-password">Password</label>
          <input id="login-password" autoComplete="current-password" className="w-full mb-6" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />

          <button
            type="submit"
            disabled={login.isPending}
            className="w-full py-2 bg-accent hover:bg-accent-hover text-white font-medium transition-colors disabled:opacity-50"
          >
            {login.isPending ? 'Signing in...' : 'Sign In'}
          </button>
        </form>

        {status?.oidc_enabled && (
          <>
            <div className="flex items-center gap-3 my-5">
              <div className="flex-1 h-px bg-border" />
              <span className="text-xs text-text-muted">or</span>
              <div className="flex-1 h-px bg-border" />
            </div>
            <a
              href="/api/auth/oidc/login"
              className="block w-full py-2 text-center border border-border hover:border-accent text-text-secondary hover:text-text-primary font-medium transition-colors"
            >
              Sign in with SSO
            </a>
          </>
        )}
      </div>
    </div>
  )
}
