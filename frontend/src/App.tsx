import { useEffect, useState } from 'react'

interface Health {
  status: string
  version: string
  redis_ok: boolean
  db_ok: boolean
}

function App() {
  const [health, setHealth] = useState<Health | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetch('/api/v1/health')
      .then((r) => r.json())
      .then(setHealth)
      .catch((e: unknown) => setError(String(e)))
  }, [])

  return (
    <main style={{ padding: 48, maxWidth: 640 }}>
      <h1 style={{ fontFamily: 'monospace', marginBottom: 4 }}>MASA</h1>
      <p style={{ color: '#9ba3a9', marginTop: 0 }}>
        Mobile Application Security Assistant — M0 scaffold
      </p>

      {error && (
        <p style={{ color: '#c1554a', fontFamily: 'monospace', fontSize: 13 }}>
          Backend unreachable: {error}
        </p>
      )}

      {health && (
        <ul
          style={{
            fontFamily: 'monospace',
            fontSize: 13,
            color: '#9ba3a9',
            listStyle: 'none',
            padding: 0,
          }}
        >
          <li>status: {health.status}</li>
          <li>version: {health.version}</li>
          <li>redis: {health.redis_ok ? 'ok' : 'down'}</li>
          <li>db: {health.db_ok ? 'ok' : 'down'}</li>
        </ul>
      )}
    </main>
  )
}

export default App
