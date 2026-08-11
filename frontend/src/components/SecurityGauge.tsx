/**
 * Security gauge - the Overview tab's SVG arc (mockup 1:1, re-themed).
 *
 * A 180° arc with a stroke-dasharray fill proportional to the score. The
 * score is the public-facing SECURITY score (100 - risk): higher is better.
 *
 * Scoring is CVSS 4.0 (owner decision, Aug 7): each severity band maps to a
 * CVSS 4.0 base score (high 8.0, medium 5.5, low 2.0, info 0) and the
 * overall risk is driven by the WORST finding plus a breadth bonus within
 * its severity band, capped at the band's CVSS 4.0 ceiling (high 89 ·
 * medium 69 · low 39 - the removed critical band is never re-introduced).
 * 11 highs = 89 · 1 high = 80 · 16 mediums = 69 · 1 medium = 55. The label
 * follows the CVSS 4.0 qualitative bands of the underlying risk - a 60/100
 * security score means risk 40 → CVSS 4.0 Medium → "Medium security" (not
 * "High").
 *
 * The arc color snaps to the CVSS 4.0 band of the underlying risk instead
 * of a continuous ramp, so the band boundaries read at a glance: risk
 * 70–89 crimson (worst) · 40–69 amber · 1–39 olive · 0 bright emerald
 * (owner decision, Aug 7 - discrete bands, not a gradient).
 */

const ARC_RADIUS = 60
const ARC_LENGTH = Math.PI * ARC_RADIUS

type RiskBand = 'High' | 'Medium' | 'Low' | 'None'

/** CVSS 4.0 qualitative severity band for the underlying risk score. */
function riskBand(risk: number): { band: RiskBand; label: string } {
  if (risk >= 70) return { band: 'High', label: 'Low security' }
  if (risk >= 40) return { band: 'Medium', label: 'Medium security' }
  if (risk > 0) return { band: 'Low', label: 'High security' }
  return { band: 'None', label: 'Excellent security' }
}

/**
 * Discrete arc color per CVSS 4.0 qualitative band, on the security-score
 * scale (higher = better): high risk = solid red, none = bright green.
 */
const BAND_COLOR: Record<RiskBand, string> = {
  // security 20-30 (risk 70-80) - solid crimson
  High: 'var(--color-crimson)',
  // security 31-60 (risk 40-69) - amber
  Medium: 'var(--color-amber)',
  // security 61-99 (risk 1-39) - muted green
  Low: 'hsl(70 55% 45%)',
  // security 100 (risk 0) - bright emerald
  None: 'var(--color-emerald)',
}

export function SecurityGauge({ score }: { score: number | null }) {
  const clamped = score == null ? 0 : Math.max(0, Math.min(100, score))
  const dash = (clamped / 100) * ARC_LENGTH
  const risk = 100 - clamped
  const { band, label } = riskBand(risk)
  const color = BAND_COLOR[band]

  return (
    <div className="flex flex-col items-center">
      <svg
        width="140"
        height="90"
        viewBox="0 0 140 90"
        role="img"
        aria-label={score == null ? 'No security score' : `Security score ${clamped} out of 100`}
      >
        {/* Track */}
        <path
          d="M 10 80 A 60 60 0 0 1 130 80"
          fill="none"
          stroke="var(--color-line)"
          strokeWidth="10"
          strokeLinecap="round"
        />
        {/* Score arc */}
        <path
          d="M 10 80 A 60 60 0 0 1 130 80"
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={`${dash} ${ARC_LENGTH}`}
          style={{ transition: 'stroke 0.3s ease, stroke-dasharray 0.5s ease' }}
        />
        {/* Score centered INSIDE the bowl (below the curve) - an HTML
          * negative-margin overlay drifted up into the arc stroke and the
          * text corners collided with the curve (owner report, Aug 8). An
          * SVG <text> at (70, 64) with text-anchor=middle always sits in the
          * arc's empty interior, regardless of font metrics. */}
        <text
          x="70"
          y="64"
          textAnchor="middle"
          fontFamily="var(--font-mono)"
          fontSize="30"
          fontWeight="700"
          fill={color}
        >
          {score == null ? '-' : clamped}
          <tspan fontSize="13" fontWeight="400" fill="var(--color-bone-faint)">
            /100
          </tspan>
        </text>
      </svg>
      <div
        className="mt-1 font-mono text-[10.5px] uppercase tracking-[0.1em]"
        style={{ color }}
      >
        {score == null ? 'No security score' : label}
      </div>
      {score != null && (
        <div className="mt-0.5 font-mono text-[9.5px] text-bone-faint">
          CVSS 4.0 · risk {risk}/100 · {band}
        </div>
      )}
    </div>
  )
}
