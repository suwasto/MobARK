/**
 * The MASA brand mark — inline vector geometry from
 * docs/icons/masa_icon_only.svg (drop-shadow filters dropped; they only
 * matter at display sizes). Crisp at any size, zero network.
 */
export function BrandMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 301 263" fill="none" aria-hidden="true" className={className}>
      <path d="M71 3L209.5 84.5V147L70.8135 67.5L71 3Z" fill="#1ED394" />
      <path d="M4 43.5L71 3V67.5L58 75L4 43.5Z" fill="#018A5E" />
      <path d="M4 43.5L58 75V122H4V43.5Z" fill="#0EB47B" />
      <path d="M4 122H58V181L4 213.5V122Z" fill="#23CF92" />
      <path d="M4 213L58.5 180L75 191V254.5L4 213Z" fill="#23CF92" />
      <path d="M75 191L97 175L152.5 209L75 254.5V191Z" fill="#017452" />
      <path
        d="M229.707 252.591L87.9998 172.633L87.9998 102L229 186L229.707 252.591Z"
        fill="#FDFFFF"
      />
      <path d="M296.017 210.97L229.707 252.591L229 186L240 180L296.017 210.97Z" fill="#FEFFFD" />
      <path
        d="M296.017 210.97L240 180L240 133.5L294.698 132.481L296.017 210.97Z"
        fill="#FEFFFC"
      />
      <path
        d="M294.698 132.481L240 133.5L239.5 76L293.16 40.9942L294.698 132.481Z"
        fill="#ECEFEF"
      />
      <path
        d="M293.168 41.4941L239.5 76L223.5 67.5L221.481 1.19325L293.168 41.4941Z"
        fill="#FCFDFC"
      />
      <path d="M223.5 67.5L203 81L145.5 47L221.481 1.19328L223.5 67.5Z" fill="#EEEFEF" />
    </svg>
  )
}
