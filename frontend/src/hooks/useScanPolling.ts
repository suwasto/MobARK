import { useEffect, useRef } from 'react'

/**
 * Polls `onTick` every `intervalMs` while `active` is true (the M5 progress
 * screen contract: 2.5s while a scan is queued/running). The callback lives
 * in a ref so the interval never resets on re-render.
 */
export function useScanPolling(
  active: boolean,
  onTick: () => void,
  intervalMs = 2500,
): void {
  const tickRef = useRef(onTick)
  useEffect(() => {
    tickRef.current = onTick
  }, [onTick])

  useEffect(() => {
    if (!active) return
    const id = window.setInterval(() => tickRef.current(), intervalMs)
    return () => window.clearInterval(id)
  }, [active, intervalMs])
}
