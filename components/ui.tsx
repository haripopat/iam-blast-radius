'use client'

/**
 * Shared presentation primitives.
 *
 * The severity palette and the evidence receipt live here because both are
 * used by three different panels and must stay identical across them — a
 * finding that renders "critical" in one place and a slightly different red in
 * another undermines the one thing this tool sells, which is that the colours
 * mean something.
 */

import type { ReactNode } from 'react'
import type { Severity, SourceRef } from '@/lib/iam/types'

export const SEVERITY: Record<Severity, { colour: string; rank: number }> = {
  critical: { colour: 'var(--color-sev-critical)', rank: 0 },
  high: { colour: 'var(--color-sev-high)', rank: 1 },
  medium: { colour: 'var(--color-sev-medium)', rank: 2 },
  low: { colour: 'var(--color-sev-low)', rank: 3 },
  info: { colour: 'var(--color-sev-info)', rank: 4 },
}

export function shortName(arn: string) {
  const slash = arn.lastIndexOf('/')
  if (slash !== -1) return arn.slice(slash + 1)
  const colon = arn.lastIndexOf(':')
  return colon === -1 ? arn : arn.slice(colon + 1)
}

/** A pill whose colour is set by one CSS colour value, tinted consistently. */
export function Tag({
  colour,
  children,
  title,
}: {
  colour: string
  children: ReactNode
  title?: string
}) {
  return (
    <span
      className="tag"
      title={title}
      style={{
        color: colour,
        borderColor: `color-mix(in oklab, ${colour} 34%, transparent)`,
        background: `color-mix(in oklab, ${colour} 11%, transparent)`,
      }}
    >
      {children}
    </span>
  )
}

export function Dot({ colour, pulse = false }: { colour: string; pulse?: boolean }) {
  return (
    <span className="relative flex h-2 w-2 shrink-0">
      {pulse && (
        <span
          className="absolute inset-0 rounded-full"
          style={{ background: colour, animation: 'ring 2.2s ease-out infinite' }}
        />
      )}
      <span className="relative h-2 w-2 rounded-full" style={{ background: colour }} />
    </span>
  )
}

/**
 * Section rule. Deliberately quiet: a small label and a hairline.
 *
 * This used to carry a big display numeral and a sentence of explanation per
 * section, which meant three lines of chrome before every piece of actual
 * content and a numbering scheme the reader had to track. A section marker
 * should tell you where you are, not compete with what you came to read.
 */
export function SectionHeading({
  title,
  right,
}: {
  title: string
  right?: ReactNode
}) {
  return (
    <div className="mb-3 flex items-center gap-3">
      <h2 className="text-[11px] font-semibold tracking-[0.14em] text-ink-dim uppercase">
        {title}
      </h2>
      <div className="hairline min-w-6 flex-1" />
      {right}
    </div>
  )
}

/**
 * The receipt. Every claim this tool makes ends in one of these: the file, the
 * JSON pointer, the line, and the literal statement. The line gutter is real —
 * it counts up from the statement's own start line so a reader can open the
 * file and land on it.
 */
export function Evidence({ refs, tone = 'cold' }: { refs: SourceRef[]; tone?: 'cold' | 'hot' }) {
  if (refs.length === 0) return null
  const accent = tone === 'hot' ? 'var(--color-hot)' : 'var(--color-cold)'

  return (
    <div className="mt-3 space-y-2">
      {refs.map((ref, i) => {
        const lines = ref.snippet.split('\n')
        const first = ref.line ?? 1
        return (
          <div key={`${ref.file}${ref.pointer}${i}`} className="receipt">
            <div className="flex flex-wrap items-center gap-x-2 gap-y-1 border-b border-line px-3 py-2 font-mono text-[10.5px]">
              <svg width="11" height="11" viewBox="0 0 12 12" fill="none" className="shrink-0">
                <path
                  d="M2.5 1.5h4L9.5 4.5v6h-7z"
                  stroke={accent}
                  strokeWidth="1"
                  strokeLinejoin="round"
                />
                <path d="M6.5 1.5v3h3" stroke={accent} strokeWidth="1" strokeLinejoin="round" />
              </svg>
              <span style={{ color: accent }}>{ref.file}</span>
              <span className="text-ink-faint">{ref.pointer}</span>
              {ref.line ? <span className="ml-auto text-ink-faint">L{ref.line}</span> : null}
            </div>
            <div className="overflow-x-auto">
              <pre className="flex px-0 py-2">
                <span
                  aria-hidden
                  className="sticky left-0 select-none border-r border-line bg-[#080b11] px-2.5 text-right text-ink-faint/50"
                >
                  {lines.map((_, n) => (
                    <span key={n} className="block">
                      {first + n}
                    </span>
                  ))}
                </span>
                <span className="px-3 text-[#b6c2d4]">
                  {lines.map((line, n) => (
                    <span key={n} className="block whitespace-pre">
                      {line}
                    </span>
                  ))}
                </span>
              </pre>
            </div>
          </div>
        )
      })}
    </div>
  )
}
