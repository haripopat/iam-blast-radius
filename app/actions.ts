'use server'

import { loadSample, loadFromText } from '@/lib/iam/load'
import { answerQuestion, Answer } from '@/lib/iam/query'
import { parseQuestionWithModel } from '@/lib/iam/enhance'
import { analyseAccount } from '@/lib/iam/rules'
import { Finding } from '@/lib/iam/types'

export interface AnalysisPayload {
  accountName: string
  accountId: string
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

function toPayload(engine: ReturnType<typeof loadSample>['engine']): AnalysisPayload {
  const account = engine.account
  return {
    accountName: account.name,
    accountId: account.id,
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
  const { engine } = loadSample(slug)
  return toPayload(engine)
}

export async function analyseUploaded(text: string): Promise<AnalysisPayload> {
  const { engine } = loadFromText(text)
  return toPayload(engine)
}

export async function ask(
  slug: string,
  question: string,
  resourceOverride?: string
): Promise<Answer> {
  const { engine } = loadSample(slug)

  // The model gets first go at understanding the question. If it is
  // unavailable or returns anything we cannot verify, the deterministic
  // parser answers instead — the engine behind it is identical either way.
  const modelParsed = resourceOverride
    ? null
    : await parseQuestionWithModel(engine, question)

  return answerQuestion(engine, question, resourceOverride, modelParsed ?? undefined)
}
