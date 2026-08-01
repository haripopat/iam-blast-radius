'use client'

/**
 * The answer, in two temperatures.
 *
 * Left is cold: principals a permissions report would already have told you
 * about. Right is hot: principals no policy grants, who can take the action
 * anyway. The asymmetry is the product — the hot side is the only one that
 * glows, and it is the only one that carries a route.
 */

import { useEffect, useState } from 'react'
import type { Answer, DirectAccess, IndirectAccess } from '@/lib/iam/query'
import type { EscalationRoute } from '@/lib/iam/escalation'
import { Dot, Evidence, Tag, shortName } from './ui'

function useCountUp(target: number, duration = 650) {
  const [n, setN] = useState(target)
  useEffect(() => {
    let raf = 0
    const start = performance.now()
    const tick = (t: number) => {
      const p = Math.min(1, (t - start) / duration)
      setN(Math.round(target * (1 - Math.pow(1 - p, 3))))
      if (p < 1) raf = requestAnimationFrame(tick)
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [target, duration])
  return n
}

function Stat({
  label,
  value,
  suffix,
  tone,
  note,
  delay,
}: {
  label: string
  value: number | null
  suffix?: string
  tone: 'cold' | 'hot' | 'neutral'
  note: string
  delay: number
}) {
  const shown = useCountUp(value ?? 0)
  const colour =
    tone === 'hot' ? 'var(--color-hot)' : tone === 'cold' ? 'var(--color-cold)' : 'var(--color-ink)'

  return (
    <div
      className={`rise ticks relative overflow-hidden rounded-xl border p-4 ${
        tone === 'hot' ? 'panel-hot' : 'panel'
      }`}
      style={{
        animationDelay: `${delay}ms`,
        color: `color-mix(in oklab, ${colour} 30%, transparent)`,
      }}
    >
      <div className="label">{label}</div>
      <div className="mt-3 flex items-baseline gap-1.5">
        <span className="numeral text-[38px] leading-[0.85]" style={{ color: colour }}>
          {value === null ? '—' : shown}
        </span>
        {suffix && value !== null && (
          <span className="font-mono text-[11px] text-ink-dim">{suffix}</span>
        )}
      </div>
      <p className="mt-2.5 text-[11.5px] leading-snug text-ink-dim">{note}</p>
    </div>
  )
}

function Interpretation({
  answer,
  onPickResource,
}: {
  answer: Answer
  onPickResource: (resource: string) => void
}) {
  const { parsed, parsedBy } = answer
  const exact = parsed.confidence === 'exact'

  return (
    <div className="panel rise rounded-xl p-4 sm:p-5">
      <div className="flex flex-wrap items-center gap-2">
        <span className="label">Read as</span>
        <Tag
          colour={parsedBy === 'model' ? 'var(--color-amber)' : 'var(--color-cold)'}
          title={
            parsedBy === 'model'
              ? 'Gemini turned your question into this query, choosing from a fixed list of resources in this account. It did not answer it — the engine did.'
              : 'Parsed by the built-in rules. No model was called.'
          }
        >
          {parsedBy === 'model' ? 'parsed by gemini' : 'parsed by rules'}
        </Tag>
        <Tag colour={exact ? 'var(--color-cold)' : 'var(--color-amber)'}>{parsed.confidence}</Tag>
      </div>

      <p className="display mt-3 text-[19px] leading-snug text-ink">{parsed.interpretation}</p>

      <div className="mt-3 flex flex-wrap items-center gap-x-2 gap-y-1.5 font-mono text-[11.5px]">
        <span className="rounded-md border border-line-2 bg-white/[0.02] px-2 py-1 text-cold">
          {parsed.action}
        </span>
        <span className="text-ink-faint">on</span>
        <span className="max-w-full truncate rounded-md border border-line-2 bg-white/[0.02] px-2 py-1 text-ink-dim">
          {parsed.resource}
        </span>
      </div>

      {!exact && (parsed.alternatives?.length ?? 0) > 0 && (
        <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-line pt-3">
          <span className="text-[12.5px] text-ink-dim">
            More than one resource matched. Did you mean
          </span>
          {parsed.alternatives!.map((alt) => (
            <button
              key={alt.resource}
              onClick={() => onPickResource(alt.resource)}
              className="chip"
              style={{ color: 'var(--color-amber)', borderColor: 'rgba(245,165,36,.35)' }}
            >
              {alt.label}
            </button>
          ))}
        </div>
      )}

      <p className="mt-4 border-t border-line pt-3.5 text-[13.5px] leading-relaxed text-[#c3cede]">
        {answer.summary}
      </p>
    </div>
  )
}

function DirectRow({ entry }: { entry: DirectAccess }) {
  const [open, setOpen] = useState(false)
  const ref = entry.evidence[0]

  return (
    <div className="overflow-hidden rounded-lg border border-line bg-white/[0.012]">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center gap-2.5 px-3 py-2.5 text-left transition-colors hover:bg-white/[0.03]"
      >
        <Dot colour="var(--color-cold)" />
        <span className="truncate font-mono text-[13px] text-ink">{entry.name}</span>
        {entry.guardedBy && (
          <Tag
            colour="var(--color-amber)"
            title="This allow depends on a condition we cannot resolve from policy alone. The access is real, but gated."
          >
            conditional
          </Tag>
        )}
        <span className="ml-auto shrink-0 font-mono text-[10px] text-ink-faint">
          {open ? '−' : '+'}
        </span>
      </button>

      {entry.guardedBy && (
        <div className="border-t border-line px-3 py-2 font-mono text-[10.5px] leading-relaxed text-amber">
          only when{' '}
          {entry.guardedBy.map((c) => `${c.key} ${c.operator} ${c.values.join(' or ')}`).join(' and ')}
        </div>
      )}

      {open ? (
        <div className="border-t border-line px-3 pb-3">
          <Evidence refs={entry.evidence.slice(0, 3)} />
        </div>
      ) : (
        ref && (
          <div className="truncate border-t border-line px-3 py-1.5 font-mono text-[10px] text-ink-faint">
            {ref.file}
            {ref.pointer}
            {ref.line ? ` · L${ref.line}` : ''}
          </div>
        )
      )}
    </div>
  )
}

/** One proved chain, drawn as a descent. Each rung is an independent allow. */
function RouteTimeline({ route, action }: { route: EscalationRoute; action: string }) {
  return (
    <ol className="relative space-y-4 pl-1">
      <span
        aria-hidden
        className="absolute top-3 bottom-3 left-[12px] w-px"
        style={{
          background:
            'linear-gradient(180deg, rgba(255,74,92,.15), rgba(255,74,92,.55), var(--color-hot))',
        }}
      />
      {route.steps.map((step, n) => (
        <li key={n} className="relative flex gap-3">
          <span className="relative z-10 flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-hot/45 bg-void font-mono text-[10.5px] text-hot">
            {n + 1}
          </span>
          <div className="min-w-0 flex-1 pt-0.5">
            <div className="font-mono text-[11px] tracking-wide text-[#ff9a4d] uppercase">
              {step.techniqueName}
            </div>
            <p className="mt-1 text-[13px] leading-relaxed text-[#c3cede]">{step.narrative}</p>
            <div className="mt-1 font-mono text-[10px] text-ink-faint">{step.reference}</div>
            <Evidence refs={step.evidence} tone="hot" />
          </div>
        </li>
      ))}
      <li className="relative flex gap-3">
        <span
          className="relative z-10 flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-hot font-mono text-[10.5px] text-hot"
          style={{ background: 'rgba(255,74,92,.18)', boxShadow: '0 0 14px rgba(255,74,92,.5)' }}
        >
          {route.steps.length + 1}
        </span>
        <div className="min-w-0 flex-1 pt-0.5">
          <div className="font-mono text-[11px] tracking-wide text-hot uppercase">
            Perform the action
          </div>
          <p className="mt-1 text-[13px] leading-relaxed text-[#c3cede]">
            As <span className="font-mono text-ink">{shortName(route.via)}</span>, run{' '}
            <span className="font-mono text-cold">{action}</span>.
          </p>
          <Evidence refs={route.finalEvidence} tone="hot" />
        </div>
      </li>
    </ol>
  )
}

function IndirectRow({
  entry,
  action,
  openKey,
  setOpenKey,
}: {
  entry: IndirectAccess
  action: string
  openKey: string | null
  setOpenKey: (k: string | null) => void
}) {
  return (
    <>
      {entry.routes.map((route, r) => {
        const key = `${entry.principal}:${r}`
        const open = openKey === key
        const hops = route.steps.length + 1
        return (
          <div
            key={key}
            className="overflow-hidden rounded-lg border transition-colors"
            style={{
              borderColor: open ? 'rgba(255,74,92,.4)' : 'rgba(255,74,92,.18)',
              background: open ? 'rgba(255,74,92,.05)' : 'rgba(255,74,92,.025)',
            }}
          >
            <button
              onClick={() => setOpenKey(open ? null : key)}
              className="flex w-full items-center gap-2.5 px-3 py-2.5 text-left transition-colors hover:bg-hot/[0.06]"
            >
              <Dot colour="var(--color-hot)" pulse />
              <span className="truncate font-mono text-[13px] text-ink">{entry.name}</span>
              <span className="hidden truncate font-mono text-[11px] text-ink-faint sm:inline">
                {route.via === entry.principal
                  ? '→ escalated membership'
                  : `→ ${shortName(route.via)}`}
              </span>
              <span className="ml-auto flex shrink-0 items-center gap-2">
                <Tag colour="var(--color-hot)">{hops} steps</Tag>
                <span className="font-mono text-[10px] text-ink-faint">{open ? '−' : '+'}</span>
              </span>
            </button>

            {open && (
              <div className="border-t border-hot/20 px-3 py-4">
                <RouteTimeline route={route} action={action} />
              </div>
            )}
          </div>
        )
      })}
    </>
  )
}

export function AnswerPanel({
  answer,
  onPickResource,
}: {
  answer: Answer
  onPickResource: (resource: string) => void
}) {
  const [openKey, setOpenKey] = useState<string | null>(null)
  const routeCount = answer.indirect.reduce((n, i) => n + i.routes.length, 0)
  const shortest = answer.indirect.length
    ? Math.min(...answer.indirect.flatMap((i) => i.routes.map((r) => r.steps.length + 1)))
    : null

  return (
    <section id="answer" className="space-y-5">
      <Interpretation answer={answer} onPickResource={onPickResource} />

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Stat
          label="Holds it directly"
          value={answer.direct.length}
          tone="cold"
          note="What any permissions report would already show you."
          delay={40}
        />
        <Stat
          label="Can take it"
          value={answer.indirect.length}
          tone="hot"
          note="No policy grants these principals the action."
          delay={100}
        />
        <Stat
          label="Shortest chain"
          value={shortest}
          suffix={shortest === 1 ? 'step' : 'steps'}
          tone="hot"
          note="Hops from a standing identity to the action."
          delay={160}
        />
        <Stat
          label="Routes proved"
          value={routeCount}
          tone="neutral"
          note="Distinct chains, every hop backed by an allow."
          delay={220}
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="panel-cold ticks rise rounded-xl p-4 text-cold/25" style={{ animationDelay: '260ms' }}>
          <div className="flex items-center gap-2.5">
            <Dot colour="var(--color-cold)" />
            <h3 className="display text-[15px] text-ink">Granted</h3>
            <span className="ml-auto font-mono text-[12px] text-cold">
              {answer.direct.length}
            </span>
          </div>
          <p className="mt-1.5 text-[12.5px] leading-snug text-ink-dim">
            Someone wrote a policy that says yes.
          </p>
          <div className="mt-3.5 space-y-2">
            {answer.direct.length === 0 ? (
              <p className="rounded-lg border border-dashed border-line px-3 py-6 text-center text-[13px] text-ink-faint">
                Nobody holds this outright.
              </p>
            ) : (
              answer.direct.map((d) => <DirectRow key={d.principal} entry={d} />)
            )}
          </div>
        </div>

        <div className="panel-hot ticks rise rounded-xl p-4 text-hot/25" style={{ animationDelay: '320ms' }}>
          <div className="flex items-center gap-2.5">
            <Dot colour="var(--color-hot)" pulse={answer.indirect.length > 0} />
            <h3 className="display text-[15px] text-ink">Reachable</h3>
            <span className="ml-auto font-mono text-[12px] text-hot">
              {answer.indirect.length}
            </span>
          </div>
          <p className="mt-1.5 text-[12.5px] leading-snug text-ink-dim">
            Nobody granted these. They can take them anyway.
          </p>
          <div className="mt-3.5 space-y-2">
            {answer.indirect.length === 0 ? (
              <p className="rounded-lg border border-dashed border-line px-3 py-6 text-center text-[13px] text-ink-faint">
                No escalation route reaches this.
              </p>
            ) : (
              answer.indirect.map((i) => (
                <IndirectRow
                  key={i.principal}
                  entry={i}
                  action={answer.parsed.action}
                  openKey={openKey}
                  setOpenKey={setOpenKey}
                />
              ))
            )}
          </div>
        </div>
      </div>
    </section>
  )
}
