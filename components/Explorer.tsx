'use client'

import { useEffect, useRef, useState, useTransition } from 'react'
import type { AnalysisPayload, Source } from '@/app/actions'
import { analyseSample, analyseSource, ask } from '@/app/actions'
import type { Answer } from '@/lib/iam/query'
import { AnswerPanel } from './AnswerPanel'
import { BlastRadiusGraph } from './BlastRadiusGraph'
import { FindingsPanel } from './FindingsPanel'
import { PastePanel } from './PastePanel'
import { QueryBar } from './QueryBar'
import { Rail } from './Rail'
import { SectionHeading } from './ui'

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

  const answerRef = useRef<HTMLDivElement>(null)
  const firstAnswer = useRef(true)

  // Bring the verdict into view the first time one arrives. Re-asking from
  // inside the panel shouldn't yank the page around, so only the first scrolls.
  useEffect(() => {
    if (!answer || !firstAnswer.current) return
    firstAnswer.current = false
    answerRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }, [answer])

  const principalCount = analysis.entities.filter((e) =>
    ['user', 'role', 'group'].includes(e.type)
  ).length

  const submit = (q: string, resourceOverride?: string) => {
    if (!q.trim()) return
    setQuestion(q)
    startTransition(async () => {
      setAnswer(await ask(source, q, resourceOverride))
    })
  }

  const changeSample = (next: string) => {
    if (!next) return
    setSource({ kind: 'sample', slug: next })
    setAnswer(null)
    firstAnswer.current = true
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
      firstAnswer.current = true
      setSource(next)
      setAnalysis(result.payload)
    })
  }

  return (
    <div className="atmosphere relative min-h-screen">
      <div className="grain" />

      <div className="relative z-10 mx-auto flex max-w-[1560px] flex-col lg:flex-row">
        <Rail
          samples={samples}
          activeSlug={source.kind === 'sample' ? source.slug : ''}
          accountName={analysis.accountName}
          accountId={analysis.accountId}
          provider={analysis.provider}
          statementCount={analysis.statementCount}
          principalCount={principalCount}
          findingCount={analysis.findings.length}
          onChangeSample={changeSample}
          onPaste={() => {
            setPasteOpen((v) => !v)
            setPasteError(null)
          }}
          pasteOpen={pasteOpen}
          busy={pending}
        />

        <main className="min-w-0 flex-1 space-y-9 px-6 pt-6 pb-20 lg:px-10 lg:pt-10 xl:px-14">
          {/* The pitch is for arrival. Once there is a real answer on the page it
              stands down, rather than sitting above the thing you came for. */}
          {!answer && (
            <header className="rise max-w-[46ch]">
              <h1 className="display text-[clamp(24px,3vw,34px)] leading-[1.12]">
                <span className="text-ink-dim">
                  Every other tool tells you who holds a permission.
                </span>{' '}
                <span className="text-ink">
                  This tells you who can{' '}
                  <span className="text-hot" style={{ textShadow: '0 0 34px rgba(255,74,92,.45)' }}>
                    take
                  </span>{' '}
                  it.
                </span>
              </h1>
            </header>
          )}

          {pasteOpen && (
            <PastePanel
              text={pasteText}
              onChange={setPasteText}
              onAnalyse={analysePaste}
              onCancel={() => {
                setPasteOpen(false)
                setPasteError(null)
              }}
              error={pasteError}
              busy={pending}
            />
          )}

          <section className="rise" style={{ animationDelay: '80ms' }}>
            <QueryBar value={question} onChange={setQuestion} onSubmit={submit} busy={pending} />
          </section>

          {answer && (
            <div ref={answerRef} className="scroll-mt-6 space-y-9">
              <AnswerPanel
                answer={answer}
                onPickResource={(resource) => submit(answer.question, resource)}
              />

              <section>
                <SectionHeading
                  title="Blast radius"
                  right={
                    <span className="hidden text-[12px] text-ink-faint sm:block">
                      red is what nobody granted
                    </span>
                  }
                />
                <BlastRadiusGraph entities={analysis.entities} answer={answer} />
              </section>
            </div>
          )}

          <section>
            <SectionHeading
              title="Findings"
              right={
                <span className="hidden text-[12px] text-ink-faint sm:block">
                  this account, independent of any question
                </span>
              }
            />
            <FindingsPanel findings={analysis.findings} />
          </section>

          <footer className="border-t border-line pt-6">
            <p className="max-w-[72ch] text-[12.5px] leading-relaxed text-ink-faint">
              Every answer on this page comes from a deterministic policy evaluator that implements
              the documented IAM evaluation rules — explicit deny beats allow, allow beats implicit
              deny. The language model only ever translates your question into a query, and never
              decides who can do what. That is why each finding can cite the exact statement behind
              it.
            </p>
          </footer>
        </main>
      </div>
    </div>
  )
}
