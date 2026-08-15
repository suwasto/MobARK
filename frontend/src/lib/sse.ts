/**
 * Minimal incremental Server-Sent Events decoder for the agent chat stream
 * (POST /scans/{id}/chat/stream). Feed text chunks as they arrive from the
 * fetch body reader; complete events come back. Handles events split across
 * network chunks, `event:`/`data:` fields, and `: comment` keepalives
 * (ignored).
 */
export interface SSEEvent {
  event: string
  data: string
}

function parseBlock(block: string): SSEEvent | null {
  let event = 'message'
  const dataLines: string[] = []
  for (const rawLine of block.split('\n')) {
    const line = rawLine.replace(/\r$/, '')
    if (line === '' || line.startsWith(':')) continue // comment / keepalive
    if (line.startsWith('event:')) {
      event = line.slice('event:'.length).trim()
    } else if (line.startsWith('data:')) {
      dataLines.push(line.slice('data:'.length).trimStart())
    }
    // Other field types (id:, retry:) are not used by MobARK's stream.
  }
  if (dataLines.length === 0) return null
  return { event, data: dataLines.join('\n') }
}

export class StreamDecoder {
  private buffer = ''

  /** Feed a chunk of stream text; returns any complete events it contains. */
  push(chunk: string): SSEEvent[] {
    this.buffer += chunk
    const events: SSEEvent[] = []
    let idx: number
    while ((idx = this.buffer.indexOf('\n\n')) !== -1) {
      const block = this.buffer.slice(0, idx)
      this.buffer = this.buffer.slice(idx + 2)
      const parsed = parseBlock(block)
      if (parsed) events.push(parsed)
    }
    return events
  }

  /** Flush a trailing partial block (end of stream). */
  flush(): SSEEvent[] {
    if (!this.buffer.trim()) return []
    const parsed = parseBlock(this.buffer)
    this.buffer = ''
    return parsed ? [parsed] : []
  }
}
