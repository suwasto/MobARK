import hljs from 'highlight.js/lib/core'
import java from 'highlight.js/lib/languages/java'
import xml from 'highlight.js/lib/languages/xml'
import kotlin from 'highlight.js/lib/languages/kotlin'
import swift from 'highlight.js/lib/languages/swift'
import objectivec from 'highlight.js/lib/languages/objectivec'
import json from 'highlight.js/lib/languages/json'
import properties from 'highlight.js/lib/languages/properties'
import ini from 'highlight.js/lib/languages/ini'
import yaml from 'highlight.js/lib/languages/yaml'
import plaintext from 'highlight.js/lib/languages/plaintext'

// Languages the decompiler serves (backend `FileContentResponse.language`).
// Registered explicitly via the core build - no CDN, local-first.
hljs.registerLanguage('java', java)
hljs.registerLanguage('xml', xml)
hljs.registerLanguage('kotlin', kotlin)
hljs.registerLanguage('swift', swift)
hljs.registerLanguage('objectivec', objectivec)
hljs.registerLanguage('json', json)
hljs.registerLanguage('properties', properties)
hljs.registerLanguage('ini', ini)
hljs.registerLanguage('yaml', yaml)
hljs.registerLanguage('plaintext', plaintext)

/** Highlight whole code with a registered language ('' → plain, unescaped). */
export function highlightCode(code: string, language: string): string {
  if (!language || !hljs.getLanguage(language)) {
    return escapeHtml(code)
  }
  try {
    return hljs.highlight(code, { language, ignoreIllegals: true }).value
  } catch {
    return escapeHtml(code)
  }
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}

/**
 * Split highlight.js output (HTML with newlines) into per-line HTML strings.
 * highlight.js can open a <span> on one line and close it on a later one;
 * each emitted line is made self-contained by re-opening the still-open tags
 * at the line start and closing them at the end (same technique as VS Code's
 * diff view / common "split highlighted code" helpers).
 */
export function splitHtmlLines(html: string): string[] {
  const lines: string[] = []
  // Stack of currently-open tags across the whole output (a span can open
  // on one line and close on a later one). `preCount` is how many of them
  // were already open when the current line began - those are re-opened as
  // the line's prefix and re-carried by updating preCount at emit.
  const tags: string[] = []
  let preCount = 0
  let current = ''

  const emit = () => {
    const closes = [...tags]
      .reverse()
      .map((tag) => {
        const m = /^<([a-zA-Z][\w-]*)/.exec(tag)
        return m ? `</${m[1]}>` : ''
      })
      .join('')
    lines.push(tags.slice(0, preCount).join('') + current + closes)
    current = ''
    preCount = tags.length
  }

  let i = 0
  while (i < html.length) {
    const ch = html[i]
    if (ch === '<') {
      const end = html.indexOf('>', i)
      if (end === -1) {
        current += html.slice(i)
        break
      }
      const tag = html.slice(i, end + 1)
      if (tag.startsWith('</')) {
        tags.pop()
      } else if (!tag.endsWith('/>') && !tag.startsWith('<!--')) {
        tags.push(tag)
      }
      current += tag
      i = end + 1
    } else if (ch === '\n') {
      emit()
      i++
    } else {
      current += ch
      i++
    }
  }
  emit()
  // highlight.js emits a trailing newline - drop the empty last line so
  // line numbers stay 1:1 with the source.
  if (lines.length > 1 && lines[lines.length - 1] === '') lines.pop()
  return lines
}
