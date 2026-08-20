import { memo, useMemo } from 'react'
import ReactMarkdown from 'react-markdown'
import remarkBreaks from 'remark-breaks'
import remarkGfm from 'remark-gfm'

const plugins = [remarkGfm, remarkBreaks]

/**
 * LLM-generated markdown (AI summary / per-finding explain / agent chat),
 * rendered by react-markdown + GFM so `**bold**`, lists, inline code and
 * code blocks display properly instead of raw syntax.
 *
 * `remark-breaks` keeps single-newline fidelity: LLM output frequently uses
 * one `\n` between clauses, and without it react-markdown would collapse
 * those into spaces (a regression vs the old `whitespace-pre-wrap`).
 *
 * Styled via the `.md` class in index.css; raw HTML in model output is
 * escaped by react-markdown by default (never injected).
 */
export const Markdown = memo(function Markdown({ text }: { text: string }) {
  const parsed = useMemo(
    () => <ReactMarkdown remarkPlugins={plugins}>{text}</ReactMarkdown>,
    [text],
  )
  return <div className="md">{parsed}</div>
})
