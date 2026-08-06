/** Human-relative timestamps for the target bar / scan lists ("2m ago"). */
export function formatRelative(iso: string, now: number = Date.now()): string {
  const t = new Date(iso).getTime()
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
