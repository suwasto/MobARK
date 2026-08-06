/**
 * Risk gauge — the Overview tab's SVG arc (mockup 1:1, re-themed).
 *
 * A 180° arc with a stroke-dasharray fill proportional to the score. The
 * color is a continuous hue ramp over the 0–100 scale — green at 0, amber
 * at 50, red at 100 — so the rating color always reflects the score. The
 * band *label* keeps the fixed severity wording (<25 low / 25–59 medium /
 * 60–84 high / >=85 critical).
 */

const ARC_RADIUS = 60
const ARC_LENGTH = Math.PI * ARC_RADIUS

function riskLabel(score: number): string {
  if (score < 25) return 'Low risk'
  if (score < 60) return 'Medium risk'
  if (score < 85) return 'High risk'
  return 'Critical risk'
}

/**
 * Color ramp over 0–100: green (hsl 120) at 0 → orange (hsl 35) at 50 →
 * red (hsl 0) at 100 — a two-segment hue lerp so the mid-range reads
 * orange rather than yellow.
 */
function scoreColor(score: number): string {
  const s = Math.max(0, Math.min(100, score)) / 100
  const hue = s < 0.5 ? 120 - 85 * (s / 0.5) : 35 - 35 * ((s - 0.5) / 0.5)
  return `hsl(${Math.round(hue)} 60% 45%)`
}

export function RiskGauge({ score }: { score: number | null }) {
  const clamped = score == null ? 0 : Math.max(0, Math.min(100, score))
  const color = scoreColor(clamped)
  const dash = (clamped / 100) * ARC_LENGTH

  return (
    <div className="flex flex-col items-center">
      <svg width="140" height="90" viewBox="0 0 140 90" aria-hidden="true">
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
      </svg>
      {/* Score overlays the arc (mockup: negative margin under the svg). */}
      <div
        className="-mt-[60px] font-mono text-[34px] font-bold leading-none"
        style={{ color }}
      >
        {score == null ? '—' : clamped}
        <span className="text-sm font-normal text-bone-faint">/100</span>
      </div>
      <div
        className="mt-1.5 font-mono text-[10.5px] uppercase tracking-[0.1em]"
        style={{ color }}
      >
        {score == null ? 'No risk score' : riskLabel(clamped)}
      </div>
    </div>
  )
}
