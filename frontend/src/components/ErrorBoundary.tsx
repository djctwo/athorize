import { Component, type ReactNode } from 'react'

interface Props {
  children: ReactNode
}

interface State {
  hasError: boolean
  error: Error | null
}

export default class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false, error: null }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error }
  }

  render() {
    if (!this.state.hasError) return this.props.children

    return (
      <div
        style={{
          minHeight: '100vh',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          background: 'var(--bg-primary)',
          color: 'var(--text-primary)',
          padding: '2rem',
        }}
      >
        <div style={{ maxWidth: 480, textAlign: 'center' }}>
          <h1
            style={{
              fontSize: '1.5rem',
              marginBottom: '0.75rem',
              color: 'var(--danger)',
            }}
          >
            Something went wrong
          </h1>
          <p
            style={{
              color: 'var(--text-secondary)',
              marginBottom: '1.5rem',
              lineHeight: 1.5,
            }}
          >
            An unexpected error occurred. Your data is safe.
          </p>
          {this.state.error && (
            <pre
              style={{
                textAlign: 'left',
                fontSize: '0.75rem',
                padding: '1rem',
                background: 'var(--bg-secondary)',
                border: '1px solid var(--border)',
                borderRadius: 4,
                overflow: 'auto',
                maxHeight: 200,
                marginBottom: '1.5rem',
                color: 'var(--text-secondary)',
              }}
            >
              {this.state.error.message}
            </pre>
          )}
          <button
            onClick={() => window.location.assign('/')}
            style={{
              padding: '0.5rem 1.5rem',
              background: 'var(--accent)',
              color: 'var(--bg-primary)',
              border: 'none',
              borderRadius: 4,
              cursor: 'pointer',
              fontWeight: 600,
            }}
          >
            Return to Dashboard
          </button>
        </div>
      </div>
    )
  }
}
