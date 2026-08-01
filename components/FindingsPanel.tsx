'use client'

/**
 * Standing findings for the account, independent of any question.
 *
 * One bordered list with dividers rather than a stack of floating cards: at a
 * dozen findings the cards read as a wall, and the severity rail down the left
 * edge is a faster scan than a repeated coloured pill. Descriptions only appear
 * on expand — the title is the finding, the rest is the argument for it.
 */

import { useMemo, useState } from 'react'
import type { Finding, Severity } from '@/lib/iam/types'
import { SEVERITY_ORDER } from '@/lib/iam/types'
import { Evidence, SEVERITY, Tag } from './ui'

const ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

function Diff({ before, after, note }: { before: string; after: string; note: string }) {
  const pane = (body: string, label: string, colour: string, sign: string) => (
    <div
      className="overflow-hidden rounded-lg border"
      style={{
        borderColor: `color-mix(in oklab, ${colour} 30%, transparent)`,
        background: `color-mix(in oklab, ${colour} 5%, transparent)`,
      }}
    >
      <div
        className="border-b px-3 py-1.5 font-mono text-[10px] tracking-[0.12em] uppercase"
        style={{ color: colour, borderColor: `color-mix(in oklab, ${colour} 22%, transparent)` }}
      >
        {label}
      </div>
      <div className="overflow-x-auto">
        <pre className="px-3 py-2 font-mono text-[11.5px] leading-[1.7] text-[#c2cde0]">
          {body.split('\n').map((line, i) => (
            <span key={i} className="block whitespace-pre">
              <span style={{ color: colour, opacity: 0.55 }}>{sign} </span>
              {line}
            </span>
          ))}
        </pre>
      </div>
    </div>
  )

  return (
    <div className="mt-4">
      <div className="label mb-2">Least-privilege rewrite, derived from this account</div>
      <div className="grid gap-2 md:grid-cols-2">
        {pane(before, 'Current', 'var(--color-hot)', '−')}
        {pane(after, 'Suggested', 'var(--color-cold)', '+')}
      </div>
      <p className="mt-2 text-[13px] leading-relaxed text-ink-dim">{note}</p>
    </div>
  )
}

function FindingRow({ finding, last }: { finding: Finding; last: boolean }) {
  const [open, setOpen] = useState(false)
  const { colour } = SEVERITY[finding.severity]

  return (
    <div className={last ? '' : 'border-b border-line'}>
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center gap-3 px-4 py-3 text-left transition-colors hover:bg-white/[0.025]"
        aria-expanded={open}
      >
        <span
          className="h-2 w-2 shrink-0 rounded-full"
          style={{ background: colour, boxShadow: `0 0 9px ${colour}` }}
        />
        <span className="min-w-0 flex-1 truncate text-[14px] text-ink">{finding.title}</span>
        {finding.confidence === 'probable' && (
          <Tag
            colour="var(--color-ink-faint)"
            title="We read intent from something soft here — a resource tag, a naming convention — rather than matching structure exactly."
          >
            inferred
          </Tag>
        )}
        <span
          className="w-[54px] shrink-0 text-right font-mono text-[11px] tracking-wider uppercase"
          style={{ color: colour }}
        >
          {finding.severity}
        </span>
      </button>

      {open && (
        <div className="border-t border-line bg-white/[0.012] px-4 py-4">
          <p className="max-w-[75ch] text-[14px] leading-relaxed text-[#c9d4e4]">
            {finding.description}
          </p>

          <div
            className="mt-3.5 rounded-lg border px-3.5 py-3"
            style={{ borderColor: 'rgba(79,216,196,.24)', background: 'rgba(79,216,196,.05)' }}
          >
            <div className="label" style={{ color: 'var(--color-cold)' }}>
              Fix
            </div>
            <p className="mt-1.5 max-w-[75ch] text-[13.5px] leading-relaxed text-[#c9d4e4]">
              {finding.remediation}
            </p>
          </div>

          {finding.rewrite && (
            <Diff
              before={finding.rewrite.before}
              after={finding.rewrite.after}
              note={finding.rewrite.note}
            />
          )}

          <div className="mt-4">
            <div className="label mb-1">Evidence</div>
            <Evidence refs={finding.evidence.slice(0, 4)} />
          </div>
        </div>
      )}
    </div>
  )
}

export function FindingsPanel({ findings }: { findings: Finding[] }) {
  const [filter, setFilter] = useState<Severity | null>(null)

  const counts = useMemo(
    () =>
      findings.reduce<Record<string, number>>((acc, f) => {
        acc[f.severity] = (acc[f.severity] ?? 0) + 1
        return acc
      }, {}),
    [findings]
  )

  const shown = useMemo(
    () =>
      [...findings]
        .filter((f) => !filter || f.severity === filter)
        .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]),
    [findings, filter]
  )

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <button
          onClick={() => setFilter(null)}
          className="chip"
          style={
            filter === null
              ? { color: 'var(--color-ink)', borderColor: 'rgba(79,216,196,.5)' }
              : undefined
          }
        >
          All {findings.length}
        </button>
        {ORDER.filter((s) => (counts[s] ?? 0) > 0).map((sev) => {
          const { colour } = SEVERITY[sev]
          const active = filter === sev
          return (
            <button
              key={sev}
              onClick={() => setFilter(active ? null : sev)}
              className="chip"
              style={{
                color: active ? colour : undefined,
                borderColor: active ? `color-mix(in oklab, ${colour} 50%, transparent)` : undefined,
                background: active ? `color-mix(in oklab, ${colour} 10%, transparent)` : undefined,
              }}
            >
              <span className="h-1.5 w-1.5 rounded-full" style={{ background: colour }} />
              {sev} {counts[sev]}
            </button>
          )
        })}
      </div>

      <div className="panel overflow-hidden rounded-xl">
        {shown.map((f, i) => (
          <FindingRow key={f.id} finding={f} last={i === shown.length - 1} />
        ))}
        {shown.length === 0 && (
          <p className="px-4 py-10 text-center text-[13.5px] text-ink-faint">
            Nothing at this severity.
          </p>
        )}
      </div>
    </div>
  )
}
