'use client'

/**
 * Standing findings for the account, independent of any question.
 *
 * These are ranked by severity and filterable, because the list is long by
 * design — an account with nothing wrong in it is not the interesting case.
 */

import { useMemo, useState } from 'react'
import type { Finding, Severity } from '@/lib/iam/types'
import { SEVERITY_ORDER } from '@/lib/iam/types'
import { Evidence, SEVERITY, Tag } from './ui'

const ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

function Diff({ before, after, note }: { before: string; after: string; note: string }) {
  const pane = (
    body: string,
    label: string,
    colour: string,
    sign: string
  ) => (
    <div
      className="overflow-hidden rounded-lg border"
      style={{
        borderColor: `color-mix(in oklab, ${colour} 30%, transparent)`,
        background: `color-mix(in oklab, ${colour} 5%, transparent)`,
      }}
    >
      <div
        className="border-b px-3 py-1.5 font-mono text-[9.5px] tracking-[0.12em] uppercase"
        style={{
          color: colour,
          borderColor: `color-mix(in oklab, ${colour} 22%, transparent)`,
        }}
      >
        {label}
      </div>
      <div className="overflow-x-auto">
        <pre className="px-3 py-2 font-mono text-[11px] leading-[1.65] text-[#b6c2d4]">
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
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <span className="label">Least-privilege rewrite</span>
        <Tag colour="var(--color-ink-faint)">derived from this account, not generated</Tag>
      </div>
      <div className="grid gap-2 md:grid-cols-2">
        {pane(before, 'Current', 'var(--color-hot)', '−')}
        {pane(after, 'Suggested', 'var(--color-cold)', '+')}
      </div>
      <p className="mt-2 text-[12px] leading-relaxed text-ink-dim">{note}</p>
    </div>
  )
}

function FindingCard({ finding, index }: { finding: Finding; index: number }) {
  const [open, setOpen] = useState(false)
  const { colour } = SEVERITY[finding.severity]

  return (
    <div
      className="rise panel overflow-hidden rounded-xl"
      style={{ animationDelay: `${Math.min(index, 8) * 45}ms` }}
    >
      <div className="flex">
        {/* Severity rail — the fastest read on the whole card. */}
        <span
          className="w-[3px] shrink-0"
          style={{ background: colour, boxShadow: `0 0 14px ${colour}` }}
        />
        <div className="min-w-0 flex-1">
          <button
            onClick={() => setOpen((v) => !v)}
            className="flex w-full items-start gap-3 px-4 py-3.5 text-left transition-colors hover:bg-white/[0.022]"
            aria-expanded={open}
          >
            <span className="min-w-0 flex-1">
              <span className="flex flex-wrap items-center gap-2">
                <span className="text-[14px] font-medium text-ink">{finding.title}</span>
                <Tag colour={colour}>{finding.severity}</Tag>
                {finding.confidence === 'probable' && (
                  <Tag
                    colour="var(--color-ink-faint)"
                    title="We read intent from something soft here — a resource tag, a naming convention — rather than matching structure exactly."
                  >
                    inferred
                  </Tag>
                )}
              </span>
              <span
                className={`mt-1.5 block text-[12.5px] leading-relaxed text-ink-dim ${
                  open ? 'hidden' : 'truncate'
                }`}
              >
                {finding.description}
              </span>
            </span>
            <span className="mt-1 shrink-0 font-mono text-[11px] text-ink-faint">
              {open ? '−' : '+'}
            </span>
          </button>

          {open && (
            <div className="border-t border-line px-4 py-4">
              <p className="text-[13.5px] leading-relaxed text-[#c3cede]">{finding.description}</p>

              <div
                className="mt-3.5 rounded-lg border px-3.5 py-3"
                style={{
                  borderColor: 'rgba(79,216,196,.24)',
                  background: 'rgba(79,216,196,.05)',
                }}
              >
                <div className="label" style={{ color: 'var(--color-cold)' }}>
                  Remediation
                </div>
                <p className="mt-1.5 text-[13px] leading-relaxed text-[#c3cede]">
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
                <span className="label">Evidence — the statements that triggered this</span>
                <Evidence refs={finding.evidence.slice(0, 4)} />
              </div>
            </div>
          )}
        </div>
      </div>
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
      <div className="mb-3.5 flex flex-wrap items-center gap-2">
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

      <div className="space-y-2.5">
        {shown.map((f, i) => (
          <FindingCard key={f.id} finding={f} index={i} />
        ))}
        {shown.length === 0 && (
          <p className="panel rounded-xl px-4 py-10 text-center text-[13px] text-ink-faint">
            Nothing at this severity.
          </p>
        )}
      </div>
    </div>
  )
}
