/**
 * Natural language -> engine call.
 *
 * This is the ONLY place language understanding happens, and it is strictly a
 * translation layer. It turns "who can delete production databases" into a
 * concrete `(action, resource)` pair, hands that to the deterministic engine,
 * and formats what comes back. It never decides who can do what.
 *
 * That separation is the whole safety argument. If the translation is wrong,
 * the user sees a wrong *question* restated in plain English and can correct
 * it — the interpretation is always shown. If we let a model answer directly,
 * a wrong answer would be indistinguishable from a right one.
 *
 * The parser here is deterministic and runs with no API key. `enhance.ts`
 * optionally layers a model on top for messier phrasing, and falls back to
 * this on any failure.
 */

import { IamEngine } from './engine'
import { escalationRoutes, EscalationRoute, short } from './escalation'
import { parseArn } from './match'
import { SourceRef } from './types'

export type VerbClass = 'delete' | 'read' | 'write' | 'admin'

const VERB_PATTERNS: { pattern: RegExp; verb: VerbClass }[] = [
  { pattern: /\b(delete|drop|destroy|remove|terminate|wipe|purge)\b/i, verb: 'delete' },
  { pattern: /\b(read|access|download|view|see|get|list|exfiltrate|steal)\b/i, verb: 'read' },
  { pattern: /\b(write|modify|change|update|edit|upload|put)\b/i, verb: 'write' },
  { pattern: /\b(admin|administrator|full control|anything|everything|take over)\b/i, verb: 'admin' },
]

/**
 * Concrete actions per service. Deliberately a small, curated table rather
 * than the full AWS action catalogue: a wrong action name produces a
 * confidently wrong answer, so we only claim the ones we are sure of.
 */
const ACTION_TABLE: Record<string, Record<VerbClass, string>> = {
  rds: {
    delete: 'rds:DeleteDBCluster',
    read: 'rds:DescribeDBClusters',
    write: 'rds:ModifyDBCluster',
    admin: 'rds:*',
  },
  s3: {
    delete: 's3:DeleteObject',
    read: 's3:GetObject',
    write: 's3:PutObject',
    admin: 's3:*',
  },
  ec2: {
    delete: 'ec2:TerminateInstances',
    read: 'ec2:DescribeInstances',
    write: 'ec2:RunInstances',
    admin: 'ec2:*',
  },
  iam: {
    delete: 'iam:DeleteUser',
    read: 'iam:GetUser',
    write: 'iam:CreateUser',
    admin: 'iam:*',
  },
  dynamodb: {
    delete: 'dynamodb:DeleteTable',
    read: 'dynamodb:GetItem',
    write: 'dynamodb:PutItem',
    admin: 'dynamodb:*',
  },
}

const STOP_WORDS = new Set([
  'who', 'can', 'what', 'which', 'the', 'a', 'an', 'is', 'are', 'to', 'on', 'in',
  'of', 'my', 'our', 'able', 'access', 'has', 'have', 'does', 'do', 'and', 'or',
  'delete', 'read', 'write', 'modify', 'get', 'list', 'view', 'see',
])

export interface ParsedQuestion {
  action: string
  resource: string
  /** Human-readable restatement of what we actually searched for */
  interpretation: string
  /** `exact` when the user named a resource we matched confidently */
  confidence: 'exact' | 'inferred'
  /** Set when we had to guess, so the UI can offer alternatives */
  alternatives?: { label: string; resource: string }[]
}

function tokens(text: string): string[] {
  return text
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((t) => t.length > 2 && !STOP_WORDS.has(t))
}

function detectVerb(question: string): VerbClass {
  for (const { pattern, verb } of VERB_PATTERNS) {
    if (pattern.test(question)) return verb
  }
  return 'admin'
}

/**
 * Score each resource in the account against the question by token overlap
 * over its name, ARN and tags.
 */
function rankResources(engine: IamEngine, question: string) {
  const qTokens = tokens(question)
  const scored = engine
    .entities('resource')
    .map((entity) => {
      const haystack = [
        entity.name,
        entity.id,
        ...Object.values(entity.tags ?? {}),
        ...Object.keys(entity.tags ?? {}),
        parseArn(entity.id)?.service ?? '',
      ]
        .join(' ')
        .toLowerCase()

      let score = 0
      for (const token of qTokens) {
        if (haystack.includes(token)) score += 2
        // "database" should match an rds resource, "bucket" an s3 one
        else if (token.startsWith('databas') && haystack.includes('rds')) score += 2
        else if ((token === 'bucket' || token === 'backup') && haystack.includes('s3')) score += 2
      }
      return { entity, score }
    })
    .filter((r) => r.score > 0)
    .sort((a, b) => b.score - a.score)

  return scored
}

export function parseQuestion(engine: IamEngine, question: string): ParsedQuestion {
  const verb = detectVerb(question)
  const ranked = rankResources(engine, question)

  if (ranked.length === 0) {
    // No resource matched. Ask about the account as a whole rather than
    // inventing a target.
    return {
      action: ACTION_TABLE.iam[verb] ?? '*',
      resource: '*',
      interpretation: `Who can perform ${ACTION_TABLE.iam[verb] ?? '*'} on any resource in the account`,
      confidence: 'inferred',
    }
  }

  const best = ranked[0]
  const service = parseArn(best.entity.id)?.service ?? 'iam'
  const action = ACTION_TABLE[service]?.[verb] ?? `${service}:*`

  return {
    action,
    resource: best.entity.id,
    interpretation: `Who can perform ${action} on ${best.entity.name}`,
    confidence: ranked.length === 1 || best.score > (ranked[1]?.score ?? 0) ? 'exact' : 'inferred',
    alternatives: ranked.slice(1, 4).map((r) => ({
      label: r.entity.name,
      resource: r.entity.id,
    })),
  }
}

// ---------------------------------------------------------------------------
// Answering
// ---------------------------------------------------------------------------

export interface DirectAccess {
  principal: string
  name: string
  evidence: SourceRef[]
}

export interface IndirectAccess {
  principal: string
  name: string
  routes: EscalationRoute[]
}

export interface Answer {
  question: string
  parsed: ParsedQuestion
  /** Which layer turned the English into a query. Shown in the UI for transparency. */
  parsedBy: 'model' | 'rules'
  direct: DirectAccess[]
  indirect: IndirectAccess[]
  /**
   * Plain-language summary. Assembled from the engine's own numbers, so it can
   * never disagree with the evidence below it.
   */
  summary: string
}

export function answerQuestion(
  engine: IamEngine,
  question: string,
  /** Set when the user picks one of the offered alternatives for an ambiguous question. */
  resourceOverride?: string,
  /** Supplied by the model layer when it successfully parsed the question. */
  modelParsed?: ParsedQuestion
): Answer {
  const base = modelParsed ?? parseQuestion(engine, question)
  const parsed: ParsedQuestion = resourceOverride
    ? {
        ...base,
        resource: resourceOverride,
        confidence: 'exact',
        interpretation: `Who can perform ${base.action} on ${
          engine.entity(resourceOverride)?.name ?? resourceOverride
        }`,
        alternatives: [
          ...(base.resource !== resourceOverride
            ? [{ label: engine.entity(base.resource)?.name ?? base.resource, resource: base.resource }]
            : []),
          ...(base.alternatives ?? []).filter((a) => a.resource !== resourceOverride),
        ],
      }
    : base
  const { action, resource } = parsed

  const direct: DirectAccess[] = []
  const indirect: IndirectAccess[] = []

  for (const principal of engine.principals()) {
    const result = engine.can(principal.id, action, resource)
    if (result.decision === 'allow') {
      direct.push({
        principal: principal.id,
        name: principal.name,
        evidence: result.matched.map((s) => s.sourceRef),
      })
      continue
    }
    const routes = escalationRoutes(engine, principal.id, action, resource)
    if (routes.length > 0) {
      indirect.push({ principal: principal.id, name: principal.name, routes })
    }
  }

  return {
    question,
    parsed,
    parsedBy: modelParsed ? 'model' : 'rules',
    direct,
    indirect,
    summary: buildSummary(parsed, direct, indirect),
  }
}

function buildSummary(
  parsed: ParsedQuestion,
  direct: DirectAccess[],
  indirect: IndirectAccess[]
): string {
  const total = direct.length + indirect.length
  if (total === 0) {
    return `Nobody in this account can perform ${parsed.action} on this resource, directly or by escalating.`
  }

  const parts: string[] = []
  parts.push(
    direct.length === 0
      ? `No principal holds ${parsed.action} on this resource outright.`
      : `${direct.length} principal${direct.length === 1 ? '' : 's'} can do this directly: ${direct.map((d) => d.name).join(', ')}.`
  )

  if (indirect.length > 0) {
    const shortest = Math.min(
      ...indirect.flatMap((i) => i.routes.map((r) => r.steps.length + 1))
    )
    parts.push(
      `A further ${indirect.length} can reach it by escalating first: ${indirect
        .map((i) => `${i.name} (${Math.min(...i.routes.map((r) => r.steps.length + 1))} steps)`)
        .join(', ')}. The shortest chain is ${shortest} steps.`
    )
    parts.push(
      `Those principals would not appear in a permissions report, because no policy grants them this action.`
    )
  }

  return parts.join(' ')
}

export { short }
