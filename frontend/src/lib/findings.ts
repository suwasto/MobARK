import type { FindingRead } from '../types'

/** File · line location for a finding, falling back to the tool that made it. */
export function findingLocation(f: FindingRead): string {
  if (f.file_path) {
    return f.line_number ? `${f.file_path} · line ${f.line_number}` : f.file_path
  }
  return f.tool ? `via ${f.tool}` : ''
}
