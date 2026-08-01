'use client'

/**
 * The left rail: what account we are looking at, and the standing risk readout
 * for it. It stays put while the main column scrolls, so the severity tally is
 * always on screen while you read a route.
 */

import type { Severity } from '@/lib/iam/types'
import { SEVERITY } from './ui'

const ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

const PROVIDER_LABEL: Record<string, string> = {
  aws: 'Amazon Web Services',
  ibm: 'IBM Cloud',
  azure: 'Microsoft Azure',
  gcp: 'Google Cloud',
}

/**
 * The mark: a point of origin and the rings going out from it, cut off on the
 * left. It is the blast radius, and it is also what the graph draws.
 */
export function Mark({ size = 30 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" fill="none" aria-hidden>
      <defs>
        <linearGradient id="mark-grad" x1="0" y1="32" x2="32" y2="0">
          <stop offset="0%" stopColor="var(--color-cold)" />
          <stop offset="55%" stopColor="var(--color-amber)" />
          <stop offset="100%" stopColor="var(--color-hot)" />
        </linearGradient>
      </defs>
      <circle cx="9" cy="23" r="3" fill="url(#mark-grad)" />
      <path d="M9 15.5a7.5 7.5 0 0 1 7.5 7.5" stroke="url(#mark-grad)" strokeWidth="1.9" />
      <path
        d="M9 9a14 14 0 0 1 14 14"
        stroke="url(#mark-grad)"
        strokeWidth="1.9"
        opacity="0.72"
      />
      <path
        d="M9 2.5A20.5 20.5 0 0 1 29.5 23"
        stroke="url(#mark-grad)"
        strokeWidth="1.9"
        opacity="0.4"
      />
    </svg>
  )
}

export function Rail({
  samples,
  activeSlug,
  accountName,
  accountId,
  provider,
  statementCount,
  principalCount,
  counts,
  onChangeSample,
  onPaste,
  pasteOpen,
  busy,
}: {
  samples: { slug: string; name: string }[]
  activeSlug: string
  accountName: string
  accountId: string
  provider: string
  statementCount: number
  principalCount: number
  counts: Record<string, number>
  onChangeSample: (slug: string) => void
  onPaste: () => void
  pasteOpen: boolean
  busy: boolean
}) {
  const worst = Math.max(1, ...ORDER.map((s) => counts[s] ?? 0))
  const total = ORDER.reduce((n, s) => n + (counts[s] ?? 0), 0)

  return (
    <aside className="relative z-10 shrink-0 border-line lg:sticky lg:top-0 lg:h-screen lg:w-[268px] lg:border-r">
      <div className="flex h-full flex-col gap-6 px-6 py-6 lg:px-7">
        <div className="flex items-center gap-2.5">
          <Mark />
          <div className="leading-none">
            <div className="display text-[15px] text-ink">Blast Radius</div>
            <div className="label mt-1">IAM reachability</div>
          </div>
        </div>

        <div className="hairline" />

        {/* Account under analysis */}
        <div>
          <div className="label mb-2.5">Account</div>
          <select
            value={samples.some((s) => s.slug === activeSlug) ? activeSlug : ''}
            onChange={(e) => onChangeSample(e.target.value)}
            className="select w-full px-3 py-2 text-[12.5px]"
            aria-label="Account under analysis"
          >
            {!samples.some((s) => s.slug === activeSlug) && (
              <option value="">{accountName}</option>
            )}
            {samples.map((s) => (
              <option key={s.slug} value={s.slug}>
                {s.name}
              </option>
            ))}
          </select>

          <dl className="mt-3 space-y-1.5 font-mono text-[11px]">
            <div className="flex items-baseline justify-between gap-2">
              <dt className="text-ink-faint">provider</dt>
              <dd className="truncate text-cold" title={PROVIDER_LABEL[provider] ?? provider}>
                {PROVIDER_LABEL[provider] ?? provider}
              </dd>
            </div>
            <div className="flex items-baseline justify-between gap-2">
              <dt className="text-ink-faint">id</dt>
              <dd className="truncate text-ink-dim" title={accountId}>
                {accountId}
              </dd>
            </div>
            <div className="flex items-baseline justify-between gap-2">
              <dt className="text-ink-faint">principals</dt>
              <dd className="text-ink-dim">{principalCount}</dd>
            </div>
            <div className="flex items-baseline justify-between gap-2">
              <dt className="text-ink-faint">statements</dt>
              <dd className="text-ink-dim">{statementCount}</dd>
            </div>
          </dl>

          <button
            onClick={onPaste}
            className="btn-ghost mt-4 w-full px-3 py-2 text-[12.5px]"
            style={
              pasteOpen
                ? { color: 'var(--color-cold)', borderColor: 'rgba(79,216,196,.45)' }
                : undefined
            }
          >
            {pasteOpen ? 'Close editor' : 'Paste your own policy'}
          </button>
        </div>

        <div className="hairline" />

        {/* Standing risk readout */}
        <div>
          <div className="mb-3 flex items-baseline justify-between">
            <span className="label">Findings</span>
            <span className="numeral text-[15px] leading-none text-ink">{total}</span>
          </div>
          <div className="space-y-2">
            {ORDER.map((sev) => {
              const n = counts[sev] ?? 0
              const { colour } = SEVERITY[sev]
              return (
                <div key={sev} className="flex items-center gap-2.5">
                  <span
                    className="w-[52px] shrink-0 font-mono text-[9.5px] uppercase tracking-[0.1em]"
                    style={{ color: n > 0 ? colour : 'var(--color-ink-faint)' }}
                  >
                    {sev}
                  </span>
                  <span className="h-[3px] flex-1 overflow-hidden rounded-full bg-line">
                    <span
                      className="block h-full rounded-full transition-[width] duration-700 ease-out"
                      style={{
                        width: `${(n / worst) * 100}%`,
                        background: colour,
                        boxShadow: n > 0 ? `0 0 10px ${colour}` : undefined,
                      }}
                    />
                  </span>
                  <span
                    className="w-4 shrink-0 text-right font-mono text-[11px] tabular-nums"
                    style={{ color: n > 0 ? 'var(--color-ink)' : 'var(--color-ink-faint)' }}
                  >
                    {n}
                  </span>
                </div>
              )
            })}
          </div>
        </div>

        <div className="mt-auto hidden lg:block">
          <div className="hairline mb-4" />
          <div className="flex items-center gap-2 font-mono text-[10px] text-ink-faint">
            <span
              className="h-1.5 w-1.5 rounded-full"
              style={{
                background: busy ? 'var(--color-amber)' : 'var(--color-cold)',
                boxShadow: `0 0 8px ${busy ? 'var(--color-amber)' : 'var(--color-cold)'}`,
                animation: busy ? 'blink .7s steps(1) infinite' : undefined,
              }}
            />
            {busy ? 'evaluating' : 'engine idle'}
          </div>
          <p className="mt-2.5 text-[11px] leading-relaxed text-ink-faint">
            Verdicts come from a deterministic policy evaluator. The model only ever turns your
            question into a query.
          </p>
        </div>
      </div>
    </aside>
  )
}
