'use client'

import { useEffect, useRef } from 'react'

const EXAMPLES = [
  'Who can delete the production database?',
  'Who can read our secrets?',
  'Who can decrypt the backups?',
  'Who can become an administrator?',
]

/**
 * The primary instrument. Everything else on the page is a readout of what
 * this returns, so it gets the weight: full width, a live prompt glyph, and a
 * scanline while the engine runs.
 */
export function QueryBar({
  value,
  onChange,
  onSubmit,
  busy,
}: {
  value: string
  onChange: (v: string) => void
  onSubmit: (q: string) => void
  busy: boolean
}) {
  const input = useRef<HTMLInputElement>(null)

  // "/" jumps to the question box, the way it does in every tool a security
  // engineer already has open.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== '/' || e.metaKey || e.ctrlKey) return
      const el = document.activeElement
      if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement) return
      e.preventDefault()
      input.current?.focus()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  return (
    <div>
      <div
        className={`panel flex items-center gap-3 rounded-2xl px-4 py-3 sm:px-5 ${
          busy ? 'scanning' : ''
        }`}
      >
        <span
          className="shrink-0 font-mono text-[15px] leading-none text-cold"
          style={{ animation: busy ? undefined : 'blink 1.15s steps(1) infinite' }}
          aria-hidden
        >
          &gt;
        </span>
        <input
          ref={input}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && onSubmit(value)}
          spellCheck={false}
          placeholder="Ask in plain English — who can delete the production database?"
          aria-label="Ask a question about this account"
          className="min-w-0 flex-1 bg-transparent py-2 text-[15.5px] text-ink outline-none placeholder:text-ink-faint/70"
        />
        <kbd className="hidden shrink-0 rounded border border-line-2 px-1.5 py-0.5 font-mono text-[10px] text-ink-faint sm:block">
          /
        </kbd>
        <button
          onClick={() => onSubmit(value)}
          disabled={busy || !value.trim()}
          className="btn-primary shrink-0 px-5 py-2.5 text-[13.5px]"
        >
          {busy ? 'Evaluating' : 'Ask'}
        </button>
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-2">
        <span className="label mr-1">Try</span>
        {EXAMPLES.map((ex, i) => (
          <button
            key={ex}
            onClick={() => onSubmit(ex)}
            className="chip rise"
            style={{ animationDelay: `${120 + i * 55}ms` }}
          >
            {ex}
          </button>
        ))}
      </div>
    </div>
  )
}
