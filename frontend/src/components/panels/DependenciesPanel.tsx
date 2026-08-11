import { useCallback, useEffect, useState } from 'react'
import { api } from '../../api/client'
import type { DependenciesResponse, DependencyItem } from '../../types'

interface DependenciesPanelProps {
  scanId: number
  /** Pre-fill the Agent dock with a question about a dependency — known-CVE
   * research is the M7 web-research use case (the agent searches when the
   * scan's 🌐 Web toggle is on; without it, it answers from local context). */
  onAskAgent: (question: string) => void
}

function cveQuestion(name: string): string {
  return `Does ${name} have any known CVEs? It is bundled in this app's dependencies.`
}

function FindingCounts({ item }: { item: DependencyItem }) {
  if (item.finding_count === 0) return null
  return (
    <span className="deps-counts" title={`${item.finding_count} non-suppressed code findings in this package`}>
      {item.high_count > 0 && <span className="sev-tag high">{item.high_count} high</span>}
      {item.medium_count > 0 && <span className="sev-tag medium">{item.medium_count} med</span>}
      {item.high_count === 0 && item.medium_count === 0 && (
        <span className="sev-tag info">{item.finding_count} findings</span>
      )}
    </span>
  )
}

function DepRow({
  item,
  platform,
  onAskAgent,
}: {
  item: DependencyItem
  platform: string
  onAskAgent: (q: string) => void
}) {
  const showCve =
    // iOS system dylibs are Apple's own — nothing to research per-dependency.
    !(platform === 'ios' && item.system === true)
  const display = item.label ?? item.name
  return (
    <div className="deps-row">
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="deps-name" title={item.name}>
            {display}
          </span>
          {item.label && item.label !== item.name && (
            <span className="deps-pkg">{item.name}</span>
          )}
          {item.system !== null && (
            <span className={`deps-chip ${item.system ? 'system' : 'third'}`}>
              {item.system ? 'system' : 'third-party'}
            </span>
          )}
          {item.kind === 'native' && item.abis.length > 0 && (
            <span className="deps-chip">{item.abis.join(', ')}</span>
          )}
        </div>
        <div className="deps-evidence">{item.evidence}</div>
      </div>
      <div className="flex shrink-0 items-center gap-3">
        <FindingCounts item={item} />
        {showCve && (
          <button
            type="button"
            className="link-btn shrink-0"
            title="Pre-fill the Agent dock with a known-CVE question — turn on 🌐 Web research for this scan to let the agent search"
            onClick={() => onAskAgent(cveQuestion(display))}
          >
            Check known CVEs
          </button>
        )}
      </div>
    </div>
  )
}

/** Dependencies tab: local-first inventory derived from the scan output
 * (nothing leaves the machine). Android: Java/Kotlin library groups + native
 * libs + runtime engines; iOS: linked dylibs + embedded frameworks. */
export function DependenciesPanel({ scanId, onAskAgent }: DependenciesPanelProps) {
  const [data, setData] = useState<DependenciesResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(() => {
    setLoading(true)
    setError(null)
    api
      .listDependencies(scanId)
      .then(setData)
      .catch((err: unknown) => {
        setData(null)
        setError(err instanceof Error ? err.message : String(err))
      })
      .finally(() => setLoading(false))
  }, [scanId])

  useEffect(() => {
    setData(null)
    void load()
  }, [load])

  const packages = data?.dependencies.filter((d) => d.kind === 'package') ?? []
  const natives = data?.dependencies.filter((d) => d.kind === 'native') ?? []
  const dylibs = data?.dependencies.filter((d) => d.kind === 'dylib') ?? []
  const frameworks = data?.dependencies.filter((d) => d.kind === 'framework') ?? []
  const thirdPartyDylibs = dylibs.filter((d) => d.system !== true)
  const systemDylibs = dylibs.filter((d) => d.system === true)

  return (
    <div>
      {/* App identity + runtime engines */}
      {data && (data.app.package || data.app.bundle_id) && (
        <div className="mb-7 rounded-[5px] border border-line bg-panel p-4">
          <div className="section-label mb-2">App</div>
          <div className="flex flex-wrap items-center gap-2">
            {data.platform === 'android' && data.app.package && (
              <span className="deps-chip strong">{data.app.package}</span>
            )}
            {data.platform === 'android' && data.app.min_sdk != null && (
              <span className="deps-chip">minSdk {data.app.min_sdk}</span>
            )}
            {data.platform === 'android' && data.app.target_sdk != null && (
              <span className="deps-chip">targetSdk {data.app.target_sdk}</span>
            )}
            {data.platform === 'ios' && data.app.bundle_id && (
              <span className="deps-chip strong">{data.app.bundle_id}</span>
            )}
            {data.platform === 'ios' && data.app.version && (
              <span className="deps-chip">v{data.app.version}</span>
            )}
            {data.runtime_markers.map((m) => (
              <span key={m} className="deps-chip engine">
                ⚙ {m}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* CVE research note — the M7 web-research boundary */}
      <div className="mb-6 rounded border border-dashed border-line bg-panel p-4 text-[12.5px] leading-relaxed text-bone-dim">
        Known-CVE research runs through the{' '}
        <strong className="text-bone">Agent dock</strong> — use the per-dependency{' '}
        <em>Check known CVEs</em> button to pre-fill a question, and turn on the
        dock's <strong className="text-bone">🌐 Web</strong> toggle (needs an
        Active search engine in Settings → Search &amp; research) so the agent
        can search for current advisories.
      </div>

      {loading && (
        <div className="flex items-center gap-2 rounded border border-line-soft bg-panel-raised p-4 font-mono text-[10px] uppercase tracking-[0.06em] text-steel">
          <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-steel" />
          Building dependency inventory…
        </div>
      )}

      {!loading && error && (
        <div className="flex items-start justify-between gap-4 rounded border border-crimson/30 bg-crimson/10 p-4 text-[12.5px] leading-relaxed text-bone-dim">
          <p className="font-mono text-[11.5px]">{error}</p>
          <button type="button" className="link-btn shrink-0" onClick={() => void load()}>
            Retry
          </button>
        </div>
      )}

      {!loading && !error && data && data.total === 0 && (
        <div className="rounded border border-line-soft bg-panel p-5 text-[12.5px] leading-relaxed text-bone-dim">
          No third-party dependencies detected{' '}
          {data.platform === 'ios'
            ? '— the bundle links no third-party dylibs and embeds no frameworks.'
            : '— the decompiled tree shows only the app\'s own package and the APK ships no native libraries.'}
        </div>
      )}

      {!loading && !error && data && (
        <>
          {data.truncated && (
            <div className="mb-6 rounded border border-amber/30 bg-amber/10 p-4 text-[12px] text-bone-dim">
              The source walk hit its size cap — the package list below may be
              partial (libraries with code findings are always listed).
            </div>
          )}

          {packages.length > 0 && (
            <>
              <div className="section-label">Java/Kotlin libraries</div>
              <div className="deps-card mb-7">
                {packages.map((d) => (
                  <DepRow key={`pkg:${d.name}`} item={d} platform={data.platform} onAskAgent={onAskAgent} />
                ))}
              </div>
            </>
          )}

          {natives.length > 0 && (
            <>
              <div className="section-label">Native libraries</div>
              <div className="deps-card mb-7">
                {natives.map((d) => (
                  <DepRow key={`native:${d.name}`} item={d} platform={data.platform} onAskAgent={onAskAgent} />
                ))}
              </div>
            </>
          )}

          {thirdPartyDylibs.length > 0 && (
            <>
              <div className="section-label">Third-party dylibs</div>
              <div className="deps-card mb-7">
                {thirdPartyDylibs.map((d) => (
                  <DepRow key={`dylib:${d.name}`} item={d} platform={data.platform} onAskAgent={onAskAgent} />
                ))}
              </div>
            </>
          )}

          {frameworks.length > 0 && (
            <>
              <div className="section-label">Embedded frameworks</div>
              <div className="deps-card mb-7">
                {frameworks.map((d) => (
                  <DepRow key={`fw:${d.name}`} item={d} platform={data.platform} onAskAgent={onAskAgent} />
                ))}
              </div>
            </>
          )}

          {systemDylibs.length > 0 && (
            <>
              <div className="section-label">System dylibs (Apple runtime)</div>
              <div className="deps-card">
                {systemDylibs.map((d) => (
                  <DepRow key={`sys:${d.name}`} item={d} platform={data.platform} onAskAgent={onAskAgent} />
                ))}
              </div>
            </>
          )}
        </>
      )}
    </div>
  )
}
