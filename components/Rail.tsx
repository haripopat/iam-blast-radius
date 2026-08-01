'use client'

/**
 * The left rail: which account we are looking at, and how to change it.
 *
 * It used to also carry a five-row severity meter, which duplicated the filter
 * chips above the findings list and gave the eye a second thing competing for
 * attention on load. The rail is now identity only — what am I looking at —
 * and severity lives in one place, next to the findings it filters.
 */

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
export function Mark({ size = 28 }: { size?: number }) {
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
      <path d="M9 9a14 14 0 0 1 14 14" stroke="url(#mark-grad)" strokeWidth="1.9" opacity="0.72" />
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
  findingCount,
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
  findingCount: number
  onChangeSample: (slug: string) => void
  onPaste: () => void
  pasteOpen: boolean
  busy: boolean
}) {
  const known = samples.some((s) => s.slug === activeSlug)

  return (
    <aside className="relative z-10 shrink-0 border-line lg:sticky lg:top-0 lg:h-screen lg:w-[248px] lg:border-r">
      <div className="flex h-full flex-col gap-5 px-6 py-6 lg:px-7">
        <div className="flex items-center gap-2.5">
          <Mark />
          <div className="display text-[15px] leading-none text-ink">Blast Radius</div>
        </div>

        <div className="hairline" />

        <div>
          <div className="label mb-2.5">Account</div>
          <select
            value={known ? activeSlug : ''}
            onChange={(e) => onChangeSample(e.target.value)}
            className="select w-full px-3 py-2 text-[13px]"
            aria-label="Account under analysis"
          >
            {!known && <option value="">{accountName}</option>}
            {samples.map((s) => (
              <option key={s.slug} value={s.slug}>
                {s.name}
              </option>
            ))}
          </select>

          <dl className="mt-3.5 space-y-2 text-[12.5px]">
            {[
              [PROVIDER_LABEL[provider] ?? provider, 'provider'],
              [accountId, 'account id'],
              [`${principalCount}`, principalCount === 1 ? 'principal' : 'principals'],
              [`${statementCount}`, statementCount === 1 ? 'statement' : 'statements'],
              [`${findingCount}`, findingCount === 1 ? 'finding' : 'findings'],
            ].map(([value, key]) => (
              <div key={key} className="flex items-baseline justify-between gap-2">
                <dt className="text-ink-faint">{key}</dt>
                <dd className="truncate font-mono text-ink-dim" title={value}>
                  {value}
                </dd>
              </div>
            ))}
          </dl>

          <button
            onClick={onPaste}
            className="btn-ghost mt-4 w-full px-3 py-2 text-[13px]"
            style={
              pasteOpen
                ? { color: 'var(--color-cold)', borderColor: 'rgba(79,216,196,.45)' }
                : undefined
            }
          >
            {pasteOpen ? 'Close editor' : 'Paste your own policy'}
          </button>
        </div>

        <div className="mt-auto hidden lg:block">
          <div className="flex items-center gap-2 font-mono text-[11px] text-ink-faint">
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
        </div>
      </div>
    </aside>
  )
}
