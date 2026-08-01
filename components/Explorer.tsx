'use client'

import { useState, useTransition } from 'react'
import type { AnalysisPayload, Source } from '@/app/actions'
import { analyseSample, analyseSource, ask } from '@/app/actions'
import type { Answer } from '@/lib/iam/query'
import type { Finding, Severity, SourceRef } from '@/lib/iam/types'
import { BlastRadiusGraph } from './BlastRadiusGraph'

const SEVERITY_STYLE: Record<Severity, { dot: string; text: string; badge: string }> = {
  critical: { dot: 'bg-[#f85149]', text: 'text-[#f85149]', badge: 'bg-[#f85149]/10 text-[#f85149] border-[#f85149]/30' },
  high: { dot: 'bg-[#f0883e]', text: 'text-[#f0883e]', badge: 'bg-[#f0883e]/10 text-[#f0883e] border-[#f0883e]/30' },
  medium: { dot: 'bg-[#d29922]', text: 'text-[#d29922]', badge: 'bg-[#d29922]/10 text-[#d29922] border-[#d29922]/30' },
  low: { dot: 'bg-[#58a6ff]', text: 'text-[#58a6ff]', badge: 'bg-[#58a6ff]/10 text-[#58a6ff] border-[#58a6ff]/30' },
  info: { dot: 'bg-[#8b949e]', text: 'text-[#8b949e]', badge: 'bg-[#8b949e]/10 text-[#8b949e] border-[#8b949e]/30' },
}

const EXAMPLES = [
  'Who can delete the production database?',
  'Who can read our secrets?',
  'Who can decrypt the backups?',
  'Who can become an administrator?',
]

function shortName(arn: string) {
  const slash = arn.lastIndexOf('/')
  if (slash !== -1) return arn.slice(slash + 1)
  const colon = arn.lastIndexOf(':')
  return colon === -1 ? arn : arn.slice(colon + 1)
}

function Evidence({ refs }: { refs: SourceRef[] }) {
  if (refs.length === 0) return null
  return (
    <div className="mt-3 space-y-2">
      {refs.map((ref, i) => (
        <div key={`${ref.file}${ref.pointer}${i}`} className="rounded-md border border-[#1e2635] bg-[#0b0e14]">
          <div className="flex items-center gap-2 border-b border-[#1e2635] px-3 py-1.5 font-mono text-[11px] text-[#8b949e]">
            <span className="text-[#58a6ff]">{ref.file}</span>
            <span>{ref.pointer}</span>
            {ref.line ? <span className="ml-auto">line {ref.line}</span> : null}
          </div>
          <pre className="overflow-x-auto px-3 py-2 font-mono text-[11px] leading-relaxed text-[#c9d1d9]">
            {ref.snippet}
          </pre>
        </div>
      ))}
    </div>
  )
}

function FindingCard({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false)
  const style = SEVERITY_STYLE[finding.severity]

  return (
    <div className="rounded-lg border border-[#1e2635] bg-[#111621]">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-start gap-3 px-4 py-3 text-left transition-colors hover:bg-[#161c28]"
      >
        <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${style.dot}`} />
        <span className="min-w-0 flex-1">
          <span className="flex flex-wrap items-center gap-2">
            <span className="text-sm font-medium text-[#e6edf3]">{finding.title}</span>
            <span className={`rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase ${style.badge}`}>
              {finding.severity}
            </span>
            {finding.confidence === 'probable' && (
              <span
                className="rounded border border-[#8b949e]/30 bg-[#8b949e]/10 px-1.5 py-0.5 font-mono text-[10px] text-[#8b949e]"
                title="We inferred intent here rather than matching structure exactly"
              >
                inferred
              </span>
            )}
          </span>
          {!open && (
            <span className="mt-1 block truncate text-xs text-[#8b949e]">{finding.description}</span>
          )}
        </span>
        <span className="mt-0.5 shrink-0 font-mono text-xs text-[#8b949e]">{open ? '−' : '+'}</span>
      </button>

      {open && (
        <div className="border-t border-[#1e2635] px-4 py-3">
          <p className="text-sm leading-relaxed text-[#c9d1d9]">{finding.description}</p>
          <div className="mt-3 rounded-md border border-[#238636]/30 bg-[#238636]/10 px-3 py-2">
            <div className="font-mono text-[10px] uppercase tracking-wide text-[#3fb950]">Remediation</div>
            <p className="mt-1 text-sm leading-relaxed text-[#c9d1d9]">{finding.remediation}</p>
          </div>

          {finding.rewrite && (
            <div className="mt-3">
              <div className="flex flex-wrap items-baseline gap-2 font-mono text-[10px] uppercase tracking-wide text-[#8b949e]">
                <span>Suggested least-privilege rewrite</span>
                <span className="rounded border border-[#1e2635] px-1.5 py-0.5 normal-case">
                  derived from this account, not generated
                </span>
              </div>
              <div className="mt-2 grid gap-2 md:grid-cols-2">
                <div className="overflow-hidden rounded-md border border-[#f85149]/30 bg-[#f85149]/[0.04]">
                  <div className="border-b border-[#f85149]/20 px-3 py-1.5 font-mono text-[10px] uppercase text-[#f85149]">
                    Current
                  </div>
                  <pre className="overflow-x-auto px-3 py-2 font-mono text-[11px] leading-relaxed text-[#c9d1d9]">
                    {finding.rewrite.before}
                  </pre>
                </div>
                <div className="overflow-hidden rounded-md border border-[#3fb950]/30 bg-[#3fb950]/[0.04]">
                  <div className="border-b border-[#3fb950]/20 px-3 py-1.5 font-mono text-[10px] uppercase text-[#3fb950]">
                    Suggested
                  </div>
                  <pre className="overflow-x-auto px-3 py-2 font-mono text-[11px] leading-relaxed text-[#c9d1d9]">
                    {finding.rewrite.after}
                  </pre>
                </div>
              </div>
              <p className="mt-2 text-xs leading-relaxed text-[#8b949e]">{finding.rewrite.note}</p>
            </div>
          )}
          <div className="mt-3 font-mono text-[10px] uppercase tracking-wide text-[#8b949e]">
            Evidence — the exact statements that triggered this
          </div>
          <Evidence refs={finding.evidence.slice(0, 4)} />
        </div>
      )}
    </div>
  )
}

function AnswerPanel({
  answer,
  onPickResource,
}: {
  answer: Answer
  onPickResource: (resource: string) => void
}) {
  const [openRoute, setOpenRoute] = useState<string | null>(null)

  return (
    <div className="space-y-4">
      <div className="rounded-lg border border-[#1e2635] bg-[#111621] p-4">
        <div className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-wide text-[#8b949e]">
          <span>Interpreted as</span>
          <span
            className="rounded border border-[#1e2635] px-1.5 py-0.5 normal-case"
            title={
              answer.parsedBy === 'model'
                ? 'Gemini translated your question into this query, choosing from a fixed list of resources. It did not answer it.'
                : 'Parsed by the built-in rules — no model was called.'
            }
          >
            {answer.parsedBy === 'model' ? 'parsed by Gemini' : 'parsed by rules'}
          </span>
        </div>
        <div className="mt-1 flex flex-wrap items-center gap-2">
          <code className="text-sm text-[#58a6ff]">{answer.parsed.interpretation}</code>
          <span
            className={`rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase ${
              answer.parsed.confidence === 'exact'
                ? 'border-[#3fb950]/30 bg-[#3fb950]/10 text-[#3fb950]'
                : 'border-[#d29922]/30 bg-[#d29922]/10 text-[#d29922]'
            }`}
          >
            {answer.parsed.confidence}
          </span>
        </div>
        {answer.parsed.confidence === 'inferred' && (answer.parsed.alternatives?.length ?? 0) > 0 && (
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <span className="text-xs text-[#8b949e]">
              Your question matched more than one resource. Did you mean
            </span>
            {answer.parsed.alternatives!.map((alt) => (
              <button
                key={alt.resource}
                onClick={() => onPickResource(alt.resource)}
                className="rounded-full border border-[#d29922]/40 bg-[#d29922]/10 px-2.5 py-0.5 font-mono text-[11px] text-[#d29922] transition-colors hover:bg-[#d29922]/20"
              >
                {alt.label}
              </button>
            ))}
            <span className="text-xs text-[#8b949e]">?</span>
          </div>
        )}
        <p className="mt-3 text-sm leading-relaxed text-[#c9d1d9]">{answer.summary}</p>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="rounded-lg border border-[#1e2635] bg-[#111621] p-4">
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-[#8b949e]" />
            <h3 className="text-sm font-medium text-[#e6edf3]">Direct access</h3>
            <span className="ml-auto font-mono text-xs text-[#8b949e]">{answer.direct.length}</span>
          </div>
          <p className="mt-1 text-xs text-[#8b949e]">What any permissions report would tell you.</p>
          <div className="mt-3 space-y-2">
            {answer.direct.length === 0 && (
              <p className="text-sm text-[#8b949e]">Nobody holds this outright.</p>
            )}
            {answer.direct.map((d) => (
              <div key={d.principal} className="rounded-md border border-[#1e2635] bg-[#0b0e14] px-3 py-2">
                <div className="font-mono text-sm text-[#e6edf3]">{d.name}</div>
                <div className="font-mono text-[10px] text-[#8b949e]">
                  {d.evidence[0]?.file}
                  {d.evidence[0]?.pointer}
                  {d.evidence[0]?.line ? ` (line ${d.evidence[0].line})` : ''}
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="rounded-lg border border-[#f85149]/30 bg-[#f85149]/[0.04] p-4">
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-[#f85149]" />
            <h3 className="text-sm font-medium text-[#e6edf3]">Reachable by escalation</h3>
            <span className="ml-auto font-mono text-xs text-[#f85149]">{answer.indirect.length}</span>
          </div>
          <p className="mt-1 text-xs text-[#8b949e]">
            No policy grants these principals the action. They can take it anyway.
          </p>
          <div className="mt-3 space-y-2">
            {answer.indirect.length === 0 && (
              <p className="text-sm text-[#8b949e]">No escalation paths found.</p>
            )}
            {answer.indirect.map((i) =>
              i.routes.map((route, r) => {
                const key = `${i.principal}:${r}`
                const isOpen = openRoute === key
                return (
                  <div key={key} className="rounded-md border border-[#1e2635] bg-[#0b0e14]">
                    <button
                      onClick={() => setOpenRoute(isOpen ? null : key)}
                      className="flex w-full items-center gap-2 px-3 py-2 text-left transition-colors hover:bg-[#111621]"
                    >
                      <span className="font-mono text-sm text-[#e6edf3]">{i.name}</span>
                      <span className="font-mono text-xs text-[#8b949e]">
                        {route.via === i.principal
                          ? '→ with escalated group membership'
                          : `→ ${shortName(route.via)}`}
                      </span>
                      <span className="ml-auto rounded border border-[#f85149]/30 bg-[#f85149]/10 px-1.5 py-0.5 font-mono text-[10px] text-[#f85149]">
                        {route.steps.length + 1} steps
                      </span>
                    </button>

                    {isOpen && (
                      <div className="border-t border-[#1e2635] px-3 py-3">
                        <ol className="space-y-3">
                          {route.steps.map((step, n) => (
                            <li key={n} className="flex gap-3">
                              <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-[#f85149]/40 font-mono text-[11px] text-[#f85149]">
                                {n + 1}
                              </span>
                              <div className="min-w-0 flex-1">
                                <div className="text-xs font-medium text-[#f0883e]">
                                  {step.techniqueName}
                                </div>
                                <p className="mt-0.5 text-sm leading-relaxed text-[#c9d1d9]">
                                  {step.narrative}
                                </p>
                                <div className="mt-1 font-mono text-[10px] text-[#8b949e]">
                                  {step.reference}
                                </div>
                                <Evidence refs={step.evidence} />
                              </div>
                            </li>
                          ))}
                          <li className="flex gap-3">
                            <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-[#f85149] bg-[#f85149]/20 font-mono text-[11px] text-[#f85149]">
                              {route.steps.length + 1}
                            </span>
                            <div className="min-w-0 flex-1">
                              <div className="text-xs font-medium text-[#f85149]">
                                Perform the action
                              </div>
                              <p className="mt-0.5 text-sm text-[#c9d1d9]">
                                As {shortName(route.via)}, run{' '}
                                <code className="text-[#58a6ff]">{answer.parsed.action}</code>.
                              </p>
                              <Evidence refs={route.finalEvidence} />
                            </div>
                          </li>
                        </ol>
                      </div>
                    )}
                  </div>
                )
              })
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

export function Explorer({
  samples,
  initialSlug,
  initial,
}: {
  samples: { slug: string; name: string }[]
  initialSlug: string
  initial: AnalysisPayload
}) {
  const [source, setSource] = useState<Source>({ kind: 'sample', slug: initialSlug })
  const [analysis, setAnalysis] = useState(initial)
  const [question, setQuestion] = useState('')
  const [answer, setAnswer] = useState<Answer | null>(null)
  const [pending, startTransition] = useTransition()

  const [pasteOpen, setPasteOpen] = useState(false)
  const [pasteText, setPasteText] = useState('')
  const [pasteError, setPasteError] = useState<string | null>(null)

  const counts = analysis.findings.reduce<Record<string, number>>((acc, f) => {
    acc[f.severity] = (acc[f.severity] ?? 0) + 1
    return acc
  }, {})

  const submit = (q: string, resourceOverride?: string) => {
    if (!q.trim()) return
    setQuestion(q)
    startTransition(async () => {
      setAnswer(await ask(source, q, resourceOverride))
    })
  }

  const changeSample = (next: string) => {
    setSource({ kind: 'sample', slug: next })
    setAnswer(null)
    startTransition(async () => {
      setAnalysis(await analyseSample(next))
    })
  }

  const analysePaste = () => {
    if (!pasteText.trim()) return
    startTransition(async () => {
      const next: Source = { kind: 'pasted', text: pasteText }
      const result = await analyseSource(next)
      if (!result.ok) {
        setPasteError(result.error)
        return
      }
      setPasteError(null)
      setPasteOpen(false)
      setAnswer(null)
      setSource(next)
      setAnalysis(result.payload)
    })
  }

  return (
    <div className="min-h-screen bg-[#0b0e14] text-[#e6edf3]">
      <header className="border-b border-[#1e2635] bg-[#0b0e14]/90 backdrop-blur">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center gap-4 px-6 py-4">
          <div>
            <h1 className="text-lg font-semibold tracking-tight">IAM Blast Radius</h1>
            <p className="text-xs text-[#8b949e]">
              Who can reach what, and how they get there
            </p>
          </div>

          <div className="ml-auto flex items-center gap-2">
            <select
              value={source.kind === 'sample' ? source.slug : ''}
              onChange={(e) => changeSample(e.target.value)}
              className="rounded-md border border-[#1e2635] bg-[#111621] px-3 py-1.5 text-sm text-[#e6edf3] outline-none focus:border-[#58a6ff]"
            >
              {source.kind === 'pasted' && <option value="">{analysis.accountName}</option>}
              {samples.map((s) => (
                <option key={s.slug} value={s.slug}>
                  {s.name}
                </option>
              ))}
            </select>
            <button
              onClick={() => {
                setPasteOpen((v) => !v)
                setPasteError(null)
              }}
              className="rounded-md border border-[#1e2635] bg-[#111621] px-3 py-1.5 text-sm text-[#8b949e] transition-colors hover:border-[#58a6ff] hover:text-[#e6edf3]"
            >
              Paste policy
            </button>
          </div>

          <div className="flex items-center gap-3 font-mono text-xs">
            {(['critical', 'high', 'medium'] as Severity[]).map((sev) => (
              <span key={sev} className="flex items-center gap-1.5">
                <span className={`h-2 w-2 rounded-full ${SEVERITY_STYLE[sev].dot}`} />
                <span className={SEVERITY_STYLE[sev].text}>{counts[sev] ?? 0}</span>
                <span className="text-[#8b949e]">{sev}</span>
              </span>
            ))}
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-6xl space-y-6 px-6 py-6">
        {pasteOpen && (
          <section className="rounded-lg border border-[#1e2635] bg-[#111621] p-4">
            <div className="flex items-baseline justify-between gap-4">
              <h2 className="text-sm font-medium">Analyse your own policy</h2>
              <span className="font-mono text-[10px] text-[#8b949e]">
                an IAM policy document, an array of them, or a full account manifest
              </span>
            </div>
            <textarea
              value={pasteText}
              onChange={(e) => setPasteText(e.target.value)}
              spellCheck={false}
              rows={10}
              placeholder={'{\n  "Version": "2012-10-17",\n  "Statement": [\n    { "Effect": "Allow", "Action": "*", "Resource": "*" }\n  ]\n}'}
              className="mt-3 w-full rounded-md border border-[#1e2635] bg-[#0b0e14] px-3 py-2 font-mono text-[12px] leading-relaxed text-[#c9d1d9] outline-none placeholder:text-[#3d4553] focus:border-[#58a6ff]"
            />
            {pasteError && (
              <p className="mt-2 rounded-md border border-[#f85149]/30 bg-[#f85149]/10 px-3 py-2 text-sm text-[#f85149]">
                {pasteError}
              </p>
            )}
            <div className="mt-3 flex items-center gap-2">
              <button
                onClick={analysePaste}
                disabled={pending || !pasteText.trim()}
                className="rounded-md bg-[#58a6ff] px-4 py-2 text-sm font-medium text-[#0b0e14] transition-opacity hover:opacity-90 disabled:opacity-40"
              >
                {pending ? 'Analysing…' : 'Analyse'}
              </button>
              <button
                onClick={() => {
                  setPasteOpen(false)
                  setPasteError(null)
                }}
                className="rounded-md border border-[#1e2635] px-4 py-2 text-sm text-[#8b949e] transition-colors hover:text-[#e6edf3]"
              >
                Cancel
              </button>
              <span className="ml-auto font-mono text-[10px] text-[#8b949e]">
                stays in this browser session — nothing is stored
              </span>
            </div>
          </section>
        )}

        <section>
          <div className="flex gap-2">
            <input
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && submit(question)}
              placeholder="Ask in plain English — who can delete the production database?"
              className="flex-1 rounded-lg border border-[#1e2635] bg-[#111621] px-4 py-3 text-sm outline-none placeholder:text-[#5a6472] focus:border-[#58a6ff]"
            />
            <button
              onClick={() => submit(question)}
              disabled={pending}
              className="rounded-lg bg-[#58a6ff] px-5 py-3 text-sm font-medium text-[#0b0e14] transition-opacity hover:opacity-90 disabled:opacity-50"
            >
              {pending ? 'Analysing…' : 'Ask'}
            </button>
          </div>
          <div className="mt-2 flex flex-wrap gap-2">
            {EXAMPLES.map((ex) => (
              <button
                key={ex}
                onClick={() => submit(ex)}
                className="rounded-full border border-[#1e2635] bg-[#111621] px-3 py-1 text-xs text-[#8b949e] transition-colors hover:border-[#58a6ff] hover:text-[#e6edf3]"
              >
                {ex}
              </button>
            ))}
          </div>
        </section>

        {answer && (
          <>
            <AnswerPanel
              answer={answer}
              onPickResource={(resource) => submit(answer.question, resource)}
            />
            <section>
              <h2 className="mb-2 text-sm font-medium">Blast radius</h2>
              <BlastRadiusGraph entities={analysis.entities} answer={answer} />
            </section>
          </>
        )}

        <section>
          <div className="mb-3 flex items-center gap-2">
            <h2 className="text-sm font-medium">Findings</h2>
            <span className="font-mono text-xs text-[#8b949e]">
              {analysis.findings.length} across {analysis.statementCount} statements
            </span>
          </div>
          <div className="space-y-2">
            {analysis.findings.map((f) => (
              <FindingCard key={f.id} finding={f} />
            ))}
          </div>
        </section>

        <footer className="border-t border-[#1e2635] pt-4 pb-8 text-xs leading-relaxed text-[#8b949e]">
          Every answer on this page comes from a deterministic policy evaluator that implements the
          IAM evaluation rules — explicit deny beats allow, allow beats implicit deny. The language
          model only translates your question into a query and never decides who can do what, which
          is why each finding cites the exact statement behind it.
        </footer>
      </main>
    </div>
  )
}
