/** Human-relative timestamps for the target bar / scan lists ("2m ago"). */
export function formatRelative(iso: string, now: number = Date.now()): string {
  // SQLite drops tzinfo on round-trip, so legacy/no-offset timestamps may
  // arrive without a zone marker. The backend now serializes them as UTC,
  // but tolerate naive strings by parsing them as UTC too - otherwise the
  // displayed age is off by the local timezone offset (owner report, Aug 7).
  const hasZone = /[zZ]|[+-]\d{2}:?\d{2}$/.test(iso)
  const t = new Date(hasZone ? iso : `${iso}Z`).getTime()
  if (Number.isNaN(t)) return ''
  const diff = now - t
  if (diff < 45_000) return 'just now'
  const mins = Math.floor(diff / 60_000)
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  if (days === 1) return 'yesterday'
  if (days < 7) return `${days}d ago`
  return new Date(t).toLocaleDateString()
}

/** Capitalized platform label for the target bar / header sub-line. */
export function platformLabel(platform: string | null): string {
  if (platform === 'android') return 'Android'
  if (platform === 'ios') return 'iOS'
  return platform ?? ''
}
