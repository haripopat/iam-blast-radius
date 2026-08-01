'use server'

import { loadSample, loadFromText } from '@/lib/iam/load'
import { answerQuestion, Answer } from '@/lib/iam/query'
import { parseQuestionWithModel } from '@/lib/iam/enhance'
import { analyseAccount } from '@/lib/iam/rules'
import { Finding } from '@/lib/iam/types'
import type { IamEngine } from '@/lib/iam/engine'

/**
 * Where the account under analysis came from. A pasted policy carries its own
 * text rather than a slug, so questions asked against it re-parse the same
 * input — there is no server-side session to go stale.
 */
export type Source = { kind: 'sample'; slug: string } | { kind: 'pasted'; text: string }

export interface AnalysisPayload {
  accountName: string
  accountId: string
  provider: string
  findings: Finding[]
  entities: {
    id: string
    name: string
    type: string
    memberOf?: string[]
    tags?: Record<string, string>
  }[]
  statementCount: number
}

function engineFor(source: Source) {
  return source.kind === 'sample' ? loadSample(source.slug) : loadFromText(source.text)
}

function toPayload(engine: IamEngine): AnalysisPayload {
  const account = engine.account
  return {
    accountName: account.name,
    accountId: account.id,
    provider: account.provider,
    findings: analyseAccount(engine),
    entities: account.entities.map((e) => ({
      id: e.id,
      name: e.name,
      type: e.type,
      memberOf: e.memberOf,
      tags: e.tags,
    })),
    statementCount: account.policies.reduce((n, p) => n + p.statements.length, 0),
  }
}

export async function analyseSample(slug: string): Promise<AnalysisPayload> {
  return toPayload(loadSample(slug).engine)
}

/**
 * Returns a result rather than throwing: a rejected server action surfaces to
 * the client as a generic render error, which would hide the parse message the
 * user actually needs to fix their paste.
 */
export async function analyseSource(
  source: Source
): Promise<{ ok: true; payload: AnalysisPayload } | { ok: false; error: string }> {
  try {
    return { ok: true, payload: toPayload(engineFor(source).engine) }
  } catch (err) {
    return { ok: false, error: (err as Error).message }
  }
}

export async function ask(
  source: Source,
  question: string,
  resourceOverride?: string
): Promise<Answer> {
  const { engine } = engineFor(source)

  // The model gets first go at understanding the question. If it is
  // unavailable or returns anything we cannot verify, the deterministic
  // parser answers instead — the engine behind it is identical either way.
  const modelParsed = resourceOverride
    ? null
    : await parseQuestionWithModel(engine, question)

  return answerQuestion(engine, question, resourceOverride, modelParsed ?? undefined)
}
