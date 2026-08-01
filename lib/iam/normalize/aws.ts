/**
 * AWS IAM JSON -> normalised model.
 *
 * AWS policy documents are permissive about shape: `Action` may be a string or
 * an array, `Principal` may be `"*"` or an object of arrays, `Resource` may be
 * absent on trust policies. Every one of those variations is a place where a
 * naive parser silently drops a permission and the tool then under-reports.
 * So this file is deliberately boring and total.
 */

import { Account, Condition, Entity, Policy, PolicyKind, Principal, Statement } from '../types'

// Shape of a raw AWS policy document as it appears on disk.
interface RawStatement {
  Sid?: string
  Effect?: string
  Action?: string | string[]
  NotAction?: string | string[]
  Resource?: string | string[]
  NotResource?: string | string[]
  Principal?: RawPrincipal
  NotPrincipal?: RawPrincipal
  Condition?: Record<string, Record<string, string | string[]>>
}

type RawPrincipal =
  | string
  | {
      AWS?: string | string[]
      Service?: string | string[]
      Federated?: string | string[]
      CanonicalUser?: string | string[]
    }

export interface RawPolicyDocument {
  Version?: string
  Statement?: RawStatement | RawStatement[]
}

function toArray<T>(value: T | T[] | undefined): T[] {
  if (value === undefined) return []
  return Array.isArray(value) ? value : [value]
}

function parsePrincipals(raw: RawPrincipal | undefined): Principal[] {
  if (raw === undefined) return []
  if (typeof raw === 'string') {
    return raw === '*' ? [{ type: 'wildcard', id: '*' }] : [{ type: 'account', id: raw }]
  }

  const out: Principal[] = []
  for (const id of toArray(raw.AWS)) {
    if (id === '*') out.push({ type: 'wildcard', id: '*' })
    else if (id.endsWith(':root')) out.push({ type: 'account', id })
    else if (id.includes(':role/')) out.push({ type: 'role', id })
    else if (id.includes(':user/')) out.push({ type: 'user', id })
    else out.push({ type: 'account', id })
  }
  for (const id of toArray(raw.Service)) out.push({ type: 'service', id })
  for (const id of toArray(raw.Federated)) out.push({ type: 'federated', id })
  for (const id of toArray(raw.CanonicalUser)) out.push({ type: 'account', id })
  return out
}

function parseConditions(
  raw: RawStatement['Condition']
): Condition[] {
  if (!raw) return []
  const out: Condition[] = []
  for (const [operator, block] of Object.entries(raw)) {
    for (const [key, value] of Object.entries(block)) {
      out.push({ operator, key, values: toArray(value) })
    }
  }
  return out
}

/**
 * Find the 1-indexed line a statement appears on, by locating its Sid in the
 * raw file text. Best effort: without a Sid we return undefined rather than
 * guessing, because a wrong line number in a security finding is worse than
 * no line number.
 */
function findLine(rawText: string | undefined, sid: string | undefined): number | undefined {
  if (!rawText || !sid) return undefined
  const needle = `"${sid}"`
  const idx = rawText.indexOf(needle)
  if (idx === -1) return undefined
  return rawText.slice(0, idx).split('\n').length
}

export interface NormalizeOptions {
  /** Policy id, used to build stable statement ids for citation */
  policyId: string
  /** File the document came from, for evidence */
  file: string
  /** Raw file text, used to resolve line numbers */
  rawText?: string
  /** JSON pointer prefix, if the document is nested inside a larger file */
  pointerPrefix?: string
}

export function normalizeAwsPolicyDocument(
  doc: RawPolicyDocument,
  opts: NormalizeOptions
): Statement[] {
  const statements = toArray(doc.Statement)
  return statements.map((raw, index) => {
    const sid = raw.Sid
    const pointer = `${opts.pointerPrefix ?? ''}/Statement/${index}`
    const statement: Statement = {
      id: `${opts.policyId}#${sid ?? index}`,
      sourceRef: {
        file: opts.file,
        pointer,
        snippet: JSON.stringify(raw, null, 2),
        line: findLine(opts.rawText, sid),
      },
      effect: raw.Effect === 'Deny' ? 'Deny' : 'Allow',
      actions: toArray(raw.Action),
      resources: toArray(raw.Resource),
      conditions: parseConditions(raw.Condition),
    }

    const notActions = toArray(raw.NotAction)
    if (notActions.length > 0) statement.notActions = notActions

    const notResources = toArray(raw.NotResource)
    if (notResources.length > 0) statement.notResources = notResources

    const principals = parsePrincipals(raw.Principal)
    if (principals.length > 0) statement.principals = principals

    const notPrincipals = parsePrincipals(raw.NotPrincipal)
    if (notPrincipals.length > 0) statement.notPrincipals = notPrincipals

    return statement
  })
}

// ---------------------------------------------------------------------------
// Account manifests
// ---------------------------------------------------------------------------

/**
 * A whole account in one file. Real deployments would build this from the AWS
 * APIs or from Terraform state; for review workflows and for the demo it is a
 * single JSON document.
 */
export interface RawAccountManifest {
  provider?: string
  id: string
  name: string
  trustedAccounts?: string[]
  entities: {
    id: string
    type: Entity['type']
    name: string
    attachedPolicies?: string[]
    memberOf?: string[]
    trustPolicy?: string
    tags?: Record<string, string>
  }[]
  policies: {
    id: string
    name: string
    kind: PolicyKind
    attachedTo?: string
    document: RawPolicyDocument
  }[]
}

export function loadAwsAccount(
  manifest: RawAccountManifest,
  file: string,
  rawText?: string
): Account {
  const policies: Policy[] = manifest.policies.map((p, index) => ({
    id: p.id,
    name: p.name,
    provider: 'aws',
    kind: p.kind,
    attachedTo: p.attachedTo,
    statements: normalizeAwsPolicyDocument(p.document, {
      policyId: p.id,
      file,
      rawText,
      pointerPrefix: `/policies/${index}/document`,
    }),
  }))

  const entities: Entity[] = manifest.entities.map((e) => ({
    id: e.id,
    type: e.type,
    name: e.name,
    attachedPolicies: e.attachedPolicies ?? [],
    memberOf: e.memberOf,
    trustPolicy: e.trustPolicy,
    tags: e.tags,
  }))

  return {
    provider: 'aws',
    id: manifest.id,
    name: manifest.name,
    trustedAccounts: manifest.trustedAccounts ?? [manifest.id],
    entities,
    policies,
  }
}
