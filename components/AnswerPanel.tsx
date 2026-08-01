'use client'

/**
 * The answer.
 *
 * One sentence, then two lists. An earlier version of this panel restated the
 * same counts five times over — an interpretation block, a prose summary, four
 * stat tiles, and then the lists themselves — which made a simple answer look
 * like a dashboard. The sentence is the answer; everything below it is only
 * there to name names and show receipts.
 *
 * The two lists stay side by side because the contrast between them is the
 * product: left is what a permissions report would tell you, right is what it
 * would miss.
 */

import { useState } from 'react'
import type { Answer, DirectAccess, IndirectAccess } from '@/lib/iam/query'
import type { EscalationRoute } from '@/lib/iam/escalation'
import { Dot, Evidence, Tag, shortName } from './ui'

/**
 * The headline, built from the same two arrays the lists render, so it cannot
 * drift from what is shown underneath it.
 */
function Headline({ answer }: { answer: Answer }) {
  const d = answer.direct.length
  const i = answer.indirect.length
  const cold = 'text-cold'
  const hot = 'text-hot'

  if (d === 0 && i === 0) {
    return (
      <p className="display text-[clamp(21px,2.3vw,30px)] leading-[1.25] text-ink">
        Nobody can do this, directly or by escalating.
      </p>
    )
  }

  return (
    <p className="display text-[clamp(21px,2.3vw,30px)] leading-[1.25]">
      {d === 0 ? (
        <span className="text-ink-dim">Nobody is granted this. </span>
      ) : (
        <span className="text-ink-dim">
          <span className={cold}>{d}</span> {d === 1 ? 'principal holds' : 'principals hold'} this.{' '}
        </span>
      )}
      {i === 0 ? (
        <span className="text-ink">Nobody else can reach it.</span>
      ) : (
        <span className="text-ink">
          <span className={hot} style={{ textShadow: '0 0 30px rgba(255,74,92,.4)' }}>
            {i}
          </span>{' '}
          {d === 0 ? (i === 1 ? 'can' : 'can') : i === 1 ? 'more can' : 'more can'} take it anyway.
        </span>
      )}
    </p>
  )
}

/** What we searched for. One quiet line — it is a caption, not a finding. */
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
    <div>
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1.5 font-mono text-[12px]">
        <span className="text-cold">{parsed.action}</span>
        <span className="text-ink-faint">on</span>
        <span className="max-w-full truncate text-ink-dim" title={parsed.resource}>
          {shortName(parsed.resource)}
        </span>
        <span className="text-ink-faint">·</span>
        <span
          className="text-ink-faint"
          title={
            parsedBy === 'model'
              ? 'Gemini turned your question into this query, choosing from a fixed list of resources in this account. It did not answer it — the engine did.'
              : 'Parsed by the built-in rules. No model was called.'
          }
        >
          read by {parsedBy === 'model' ? 'gemini' : 'rules'}
        </span>
        {!exact && <Tag colour="var(--color-amber)">inferred</Tag>}
      </div>

      {!exact && (parsed.alternatives?.length ?? 0) > 0 && (
        <div className="mt-2.5 flex flex-wrap items-center gap-2">
          <span className="text-[13px] text-ink-dim">Did you mean</span>
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
    </div>
  )
}

function DirectRow({ entry }: { entry: DirectAccess }) {
  const [open, setOpen] = useState(false)

  return (
    <div className="overflow-hidden rounded-lg border border-line bg-white/[0.015]">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center gap-2.5 px-3.5 py-3 text-left transition-colors hover:bg-white/[0.035]"
      >
        <Dot colour="var(--color-cold)" />
        <span className="truncate font-mono text-[14px] text-ink">{entry.name}</span>
        {entry.guardedBy && (
          <Tag
            colour="var(--color-amber)"
            title="This allow depends on a condition we cannot resolve from policy alone. The access is real, but gated."
          >
            conditional
          </Tag>
        )}
        <span className="ml-auto shrink-0 font-mono text-[12px] text-ink-faint">
          {open ? 'hide' : 'why'}
        </span>
      </button>

      {entry.guardedBy && (
        <div className="border-t border-line px-3.5 py-2 font-mono text-[11.5px] leading-relaxed text-amber">
          only when{' '}
          {entry.guardedBy
            .map((c) => `${c.key} ${c.operator} ${c.values.join(' or ')}`)
            .join(' and ')}
        </div>
      )}

      {open && (
        <div className="border-t border-line px-3.5 pb-3.5">
          <Evidence refs={entry.evidence.slice(0, 3)} />
        </div>
      )}
    </div>
  )
}

/** One proved chain, drawn as a descent. Each rung is an independent allow. */
function RouteTimeline({ route, action }: { route: EscalationRoute; action: string }) {
  return (
    <ol className="relative space-y-4">
      <span
        aria-hidden
        className="absolute top-3 bottom-3 left-[11px] w-px"
        style={{
          background:
            'linear-gradient(180deg, rgba(255,74,92,.15), rgba(255,74,92,.55), var(--color-hot))',
        }}
      />
      {route.steps.map((step, n) => (
        <li key={n} className="relative flex gap-3.5">
          <span className="relative z-10 flex h-[23px] w-[23px] shrink-0 items-center justify-center rounded-full border border-hot/45 bg-void font-mono text-[11px] text-hot">
            {n + 1}
          </span>
          <div className="min-w-0 flex-1">
            <p className="text-[14px] leading-relaxed text-ink">{step.narrative}</p>
            <div className="mt-1 font-mono text-[11px] text-ink-faint">
              {step.techniqueName} · {step.reference}
            </div>
            <Evidence refs={step.evidence} tone="hot" />
          </div>
        </li>
      ))}
      <li className="relative flex gap-3.5">
        <span
          className="relative z-10 flex h-[23px] w-[23px] shrink-0 items-center justify-center rounded-full border border-hot font-mono text-[11px] text-hot"
          style={{ background: 'rgba(255,74,92,.18)', boxShadow: '0 0 14px rgba(255,74,92,.5)' }}
        >
          {route.steps.length + 1}
        </span>
        <div className="min-w-0 flex-1">
          <p className="text-[14px] leading-relaxed text-ink">
            As <span className="font-mono">{shortName(route.via)}</span>, run{' '}
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
              borderColor: open ? 'rgba(255,74,92,.42)' : 'rgba(255,74,92,.2)',
              background: open ? 'rgba(255,74,92,.055)' : 'rgba(255,74,92,.03)',
            }}
          >
            <button
              onClick={() => setOpenKey(open ? null : key)}
              className="flex w-full items-center gap-2.5 px-3.5 py-3 text-left transition-colors hover:bg-hot/[0.07]"
            >
              <Dot colour="var(--color-hot)" pulse />
              <span className="truncate font-mono text-[14px] text-ink">{entry.name}</span>
              <span className="ml-auto flex shrink-0 items-center gap-2.5">
                <span className="font-mono text-[12px] text-hot">in {hops} steps</span>
                <span className="font-mono text-[12px] text-ink-faint">{open ? 'hide' : 'how'}</span>
              </span>
            </button>

            {open && (
              <div className="border-t border-hot/20 px-3.5 py-4">
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

  return (
    <section id="answer" className="space-y-6">
      <div className="space-y-3.5">
        <Interpretation answer={answer} onPickResource={onPickResource} />
        <Headline answer={answer} />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="panel rounded-xl p-4">
          <div className="mb-3.5 flex items-baseline gap-2.5">
            <h3 className="text-[13px] font-semibold tracking-wide text-cold uppercase">Granted</h3>
            <p className="text-[13px] text-ink-dim">someone wrote a policy that says yes</p>
          </div>
          <div className="space-y-2">
            {answer.direct.length === 0 ? (
              <p className="rounded-lg border border-dashed border-line px-3 py-7 text-center text-[13.5px] text-ink-faint">
                Nobody holds this outright.
              </p>
            ) : (
              answer.direct.map((d) => <DirectRow key={d.principal} entry={d} />)
            )}
          </div>
        </div>

        <div className="panel-hot rounded-xl p-4">
          <div className="mb-3.5 flex items-baseline gap-2.5">
            <h3 className="text-[13px] font-semibold tracking-wide text-hot uppercase">
              Can take it
            </h3>
            <p className="text-[13px] text-ink-dim">no policy grants them this</p>
          </div>
          <div className="space-y-2">
            {answer.indirect.length === 0 ? (
              <p className="rounded-lg border border-dashed border-line px-3 py-7 text-center text-[13.5px] text-ink-faint">
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
