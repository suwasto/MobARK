import { useEffect, useState } from 'react'
import { api, ApiError } from '../../api/client'
import { BrandMark } from '../BrandMark'
import { useApp } from '../../state/AppContext'

/** OAuth callback failures land on /login?error=<code> (backend never 500s).
 * Map each code to copy the user can act on. */
const OAUTH_ERROR_COPY: Record<string, string> = {
  invalid_state: 'Sign-in state mismatch - please try again.',
  access_denied: 'Sign-in was cancelled or denied.',
  oauth_failed: 'The provider could not complete the sign-in - please try again.',
  email_not_verified:
    'That Google account has an unverified email. Verify it, then sign in again.',
}

/** OAuth provider button labels. */
const OAUTH_LABELS: Record<string, string> = {
  github: 'Continue with GitHub',
  google: 'Continue with Google',
}

type Mode = 'login' | 'register'

/** M9.1 Phase D: the auth gate screen (rendered by the shell when `auth ===
 * 'anon'`). Username/password login + register (first account = admin), and
 * GitHub/Google buttons - each rendered only when the backend reports it
 * configured (owner decision 1: no config, no button, never a broken flow).
 */
export function LoginView() {
  const { providers, actions } = useApp()
  const [mode, setMode] = useState<Mode>('login')
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  // OAuth callbacks redirect to /login?error=<code> - surface it once and
  // scrub the URL so a refresh doesn't re-show it.
  useEffect(() => {
    const code = new URLSearchParams(window.location.search).get('error')
    if (code) {
      setError(OAUTH_ERROR_COPY[code] ?? `Sign-in failed: ${code}`)
      window.history.replaceState({}, '', window.location.pathname)
    }
  }, [])

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (busy) return
    setBusy(true)
    setError(null)
    try {
      if (mode === 'login') {
        await actions.login(username, password)
      } else {
        await actions.register(username, password, email.trim() || undefined)
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const oauthProviders = (providers?.providers ?? []).filter(
    (p) => p !== 'local' && OAUTH_LABELS[p],
  )
  const firstRun = mode === 'register'

  return (
    <div className="flex h-screen items-center justify-center overflow-y-auto bg-graphite p-6">
      <div className="flex w-full max-w-[380px] flex-col py-6">
        <div className="mb-7 flex flex-col items-center text-center">
          <BrandMark className="mb-4 h-11 w-auto opacity-90" />
          <h1 className="font-mono text-[17px] font-semibold">
            {mode === 'login' ? 'Sign in to MobARK' : 'Create an account'}
          </h1>
          <p className="mt-1.5 max-w-[320px] text-[12.5px] leading-relaxed text-bone-faint">
            {firstRun
              ? 'The first account created becomes the instance admin and adopts any scans that predate it.'
              : 'Sign in to your mobile application security workspace.'}
          </p>
        </div>

        {/* Mode toggle */}
        <div className="mb-4 grid grid-cols-2 gap-1 rounded border border-line bg-panel p-1">
          {(['login', 'register'] as const).map((m) => (
            <button
              key={m}
              type="button"
              className={`rounded px-3 py-1.5 text-[12.5px] font-medium ${
                mode === m
                  ? 'bg-panel-raised text-bone'
                  : 'text-bone-faint hover:text-bone'
              }`}
              onClick={() => {
                setMode(m)
                setError(null)
              }}
            >
              {m === 'login' ? 'Sign in' : 'Create account'}
            </button>
          ))}
        </div>

        {error && (
          <div
            role="alert"
            className="mb-4 rounded border border-crimson/50 bg-crimson/10 px-3 py-2 text-[12px] leading-relaxed text-sev-red"
          >
            {error}
          </div>
        )}

        <form onSubmit={(e) => void submit(e)} className="flex flex-col gap-3">
          <label className="flex flex-col gap-1 text-[11.5px] text-bone-dim">
            Username or email
            <input
              className="auth-input"
              type="text"
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              autoFocus
            />
          </label>

          {firstRun && (
            <label className="flex flex-col gap-1 text-[11.5px] text-bone-dim">
              Email (optional)
              <input
                className="auth-input"
                type="email"
                autoComplete="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </label>
          )}

          <label className="flex flex-col gap-1 text-[11.5px] text-bone-dim">
            Password
            <input
              className="auth-input"
              type="password"
              autoComplete={firstRun ? 'new-password' : 'current-password'}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              minLength={firstRun ? 8 : 1}
            />
          </label>

          <button
            type="submit"
            className="btn btn-primary mt-1 w-full justify-center"
            disabled={busy}
          >
            {busy ? '…' : mode === 'login' ? 'Sign in' : 'Create account'}
          </button>
        </form>

        {oauthProviders.length > 0 && (
          <>
            <div className="my-4 flex items-center gap-3 text-[11px] text-bone-faint">
              <span className="h-px flex-1 bg-line" />
              or continue with
              <span className="h-px flex-1 bg-line" />
            </div>
            <div className="flex flex-col gap-2">
              {oauthProviders.map((p) => (
                <a key={p} className="btn w-full justify-center" href={api.oauthStartUrl(p)}>
                  {OAUTH_LABELS[p]}
                </a>
              ))}
            </div>
          </>
        )}

        <p className="mt-6 text-center text-[11px] text-bone-faint">
          Analysis stays on this machine - your scans never leave it.
        </p>
      </div>
    </div>
  )
}
