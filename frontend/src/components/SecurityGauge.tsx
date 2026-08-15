/**
 * Security gauge - the Overview tab's SVG arc (mockup 1:1, re-themed).
 *
 * A 180° arc with a stroke-dasharray fill proportional to the score. The
 * score is the public-facing SECURITY score (100 - risk): higher is better.
 *
 * Scoring is the banded risk index (owner decision, Aug 15, 2026 - the CVSS
 * 4.0 model was replaced: a static scanner cannot honestly assess CVSS
 * attack requirements / user interaction, so the score is a plain severity
 * heuristic instead): the worst finding picks the band - any high sets the
 * High band (risk 70), otherwise warnings set the Warning band (risk 40) -
 * plus ~1 point per extra finding at that band, capped at the band ceiling
 * (high 99 · warning 69). Info findings never score. 11 highs = 80 · 2 =
 * 71 · 1 = 70 · 30 warnings = 69. The label follows the risk-index band of
 * the underlying risk - a 60/100 security score means risk 40 → Medium →
 * "Medium security" (not "High").
 *
 * The arc color snaps to the risk band instead of a continuous ramp, so the
 * band boundaries read at a glance: risk 70-99 crimson (worst) · 40-69
 * amber · 0 bright emerald (the old 1-39 low band is unreachable under the
 * banded model and gone).
 */

const ARC_RADIUS = 60
const ARC_LENGTH = Math.PI * ARC_RADIUS

type RiskBand = 'High' | 'Medium' | 'None'

/** Risk-index band of the underlying risk score. */
function riskBand(risk: number): { band: RiskBand; label: string } {
  if (risk >= 70) return { band: 'High', label: 'Low security' }
  if (risk >= 40) return { band: 'Medium', label: 'Medium security' }
  return { band: 'None', label: 'Excellent security' }
}

/**
 * Discrete arc color per risk band, on the security-score scale (higher =
 * better): high risk = solid red, none = bright green.
 */
const BAND_COLOR: Record<RiskBand, string> = {
  // security 1-30 (risk 70-99) - solid crimson
  High: 'var(--color-crimson)',
  // security 31-60 (risk 40-69) - amber
  Medium: 'var(--color-amber)',
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
          risk {risk}/100 · {band}
        </div>
      )}
    </div>
  )
}
