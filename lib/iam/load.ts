/**
 * Loading accounts from disk. Server-only — imports node:fs.
 */

import { readFileSync, readdirSync } from 'node:fs'
import path from 'node:path'
import { parseArn } from './match'
import { buildEngine, IamEngine } from './engine'
import {
  loadAwsAccount,
  normalizeAwsPolicyDocument,
  RawAccountManifest,
  RawPolicyDocument,
} from './normalize/aws'
import { loadIbmAccount, RawIbmManifest } from './normalize/ibm'
import { Account, Entity, Policy, Principal } from './types'

const SAMPLES_DIR = path.join(process.cwd(), 'data', 'samples')

export function listSamples(): { slug: string; name: string }[] {
  return readdirSync(SAMPLES_DIR)
    .filter((f) => f.endsWith('.json'))
    .map((f) => {
      const slug = f.replace(/\.json$/, '')
      const raw = JSON.parse(readFileSync(path.join(SAMPLES_DIR, f), 'utf8'))
      return { slug, name: raw.name ?? slug }
    })
}

/**
 * Dispatch on the manifest's declared provider. Everything downstream sees the
 * same normalised `Account`, so adding a provider never touches the engine,
 * the rules, or the UI.
 */
function normalize(raw: unknown, filename: string, rawText: string): Account {
  const provider = (raw as { provider?: string }).provider ?? 'aws'
  switch (provider) {
    case 'ibm':
      return loadIbmAccount(raw as RawIbmManifest, filename, rawText)
    case 'aws':
      return loadAwsAccount(raw as RawAccountManifest, filename, rawText)
    default:
      throw new Error(`unsupported provider: ${provider}`)
  }
}

export function loadSample(slug: string): { engine: IamEngine; account: Account } {
  // Guard against path traversal — slug comes from the client.
  if (!/^[a-z0-9-]+$/i.test(slug)) throw new Error(`invalid sample: ${slug}`)
  const file = path.join(SAMPLES_DIR, `${slug}.json`)
  const rawText = readFileSync(file, 'utf8')
  const account = normalize(JSON.parse(rawText), `${slug}.json`, rawText)
  return { engine: buildEngine(account), account }
}

// ---------------------------------------------------------------------------
// Pasted input
// ---------------------------------------------------------------------------

const PASTED_ACCOUNT = '000000000000'
const PASTED_PRINCIPAL = `arn:aws:iam::${PASTED_ACCOUNT}:user/pasted-principal`
const PASTED_RESOURCE = `arn:aws:s3:::pasted-resource`

/**
 * Wrap one or more bare AWS policy documents in a synthetic account.
 *
 * Someone pasting into this tool has a policy in their clipboard, not an
 * account manifest. Rather than make them reshape it, we build the smallest
 * account that gives the policy somewhere to live: one principal to hold
 * identity policies, one resource to hold resource policies. Every downstream
 * stage — findings, escalation, the graph — then runs completely unchanged.
 *
 * A document whose statements name a `Principal` is a resource or trust
 * policy, so it attaches to the synthetic resource; everything else is an
 * identity policy on the synthetic principal.
 */
function accountFromPolicyDocuments(
  docs: RawPolicyDocument[],
  filename: string,
  rawText: string
): Account {
  const policies: Policy[] = docs.map((doc, index) => {
    const statements = normalizeAwsPolicyDocument(doc, {
      policyId: `pasted-${index}`,
      file: filename,
      rawText,
      pointerPrefix: docs.length > 1 ? `/${index}` : '',
    })
    const isResourcePolicy = statements.some((s) => (s.principals?.length ?? 0) > 0)
    return {
      id: `pasted-${index}`,
      name: docs.length > 1 ? `Pasted policy ${index + 1}` : 'Pasted policy',
      provider: 'aws' as const,
      kind: isResourcePolicy ? ('resource' as const) : ('identity' as const),
      // Attach to the resource the policy itself names, not an invented ARN.
      // A synthetic id would never match the statement's own `Resource`, so
      // the grant would silently evaluate to nothing.
      attachedTo: isResourcePolicy ? (statements[0]?.resources[0] ?? PASTED_RESOURCE) : undefined,
      statements,
    }
  })

  const identityPolicies = policies.filter((p) => p.kind === 'identity').map((p) => p.id)
  const namedResources = resourcesNamedIn(policies)

  return {
    provider: 'aws',
    id: PASTED_ACCOUNT,
    name: 'Pasted policy',
    trustedAccounts: [PASTED_ACCOUNT],
    entities: [
      // Only invent a holder when there is an identity policy for it to hold.
      // A pure resource policy has no identity in it, and listing a fictional
      // user among the answers to "who can reach this" is noise at best.
      ...(identityPolicies.length > 0
        ? [
            {
              id: PASTED_PRINCIPAL,
              type: 'user' as const,
              name: 'pasted-principal',
              attachedPolicies: identityPolicies,
            },
          ]
        : []),
      ...(namedResources.length > 0
        ? namedResources
        : [
            {
              id: PASTED_RESOURCE,
              type: 'resource' as const,
              name: 'pasted-resource',
              attachedPolicies: [],
            },
          ]),
      ...principalsNamedIn(policies),
    ],
    policies,
  }
}

/**
 * The resources a pasted resource policy names, as entities.
 *
 * These have to be the literal `Resource` strings from the policy — an S3
 * bucket policy grants on `arn:aws:s3:::bucket/*`, and asking about anything
 * else simply does not match it.
 */
function resourcesNamedIn(policies: Policy[]): Entity[] {
  const byId = new Map<string, Entity>()

  for (const policy of policies) {
    if (policy.kind !== 'resource') continue
    for (const statement of policy.statements) {
      for (const resource of statement.resources) {
        if (resource === '*' || byId.has(resource)) continue
        byId.set(resource, {
          id: resource,
          type: 'resource',
          name: resourceLabel(resource),
          attachedPolicies: [],
        })
      }
    }
  }

  return [...byId.values()]
}

function resourceLabel(resource: string): string {
  const trimmed = resource.replace(/\/\*$/, '')
  const parsed = parseArn(trimmed)
  if (parsed?.resourceId) return parsed.resourceId
  const colon = trimmed.lastIndexOf(':')
  return colon === -1 ? trimmed : trimmed.slice(colon + 1)
}

/**
 * Turn the principals a resource policy *names* into entities.
 *
 * Without this, pasting a bucket policy produces an account containing nobody
 * it grants to, so "who can read this?" answers "nobody" — the exact opposite
 * of the truth. The principals in a resource policy are the answer to that
 * question, so they have to exist as entities for the engine to return them.
 *
 * A wildcard principal becomes an entity named for what it actually means. It
 * is the single most important row this tool can show against a public bucket,
 * and burying it as `*` would waste it.
 */
function principalsNamedIn(policies: Policy[]): Entity[] {
  const byId = new Map<string, Entity>()

  for (const policy of policies) {
    if (policy.kind !== 'resource') continue
    for (const statement of policy.statements) {
      for (const principal of statement.principals ?? []) {
        if (byId.has(principal.id)) continue
        byId.set(principal.id, {
          id: principal.id,
          type: entityTypeFor(principal.type),
          name: principalLabel(principal),
          attachedPolicies: [],
        })
      }
    }
  }

  return [...byId.values()]
}

function entityTypeFor(type: Principal['type']): Entity['type'] {
  switch (type) {
    case 'user':
      return 'user'
    case 'role':
      return 'role'
    case 'service':
      return 'service'
    default:
      // Account roots, federated identities and the wildcard all stand for
      // "some set of principals we cannot enumerate", which is close enough to
      // an account for the purpose of answering who can reach a resource.
      return 'account'
  }
}

function principalLabel(principal: Principal): string {
  if (principal.type === 'wildcard' || principal.id === '*') return 'anyone on the internet'
  if (principal.type === 'service') return principal.id
  const parsed = parseArn(principal.id)
  if (parsed?.resourceType === 'root') return `anyone in account ${parsed.account}`
  const slash = principal.id.lastIndexOf('/')
  return slash === -1 ? principal.id : principal.id.slice(slash + 1)
}

function isPolicyDocument(value: unknown): value is RawPolicyDocument {
  return typeof value === 'object' && value !== null && 'Statement' in value
}

/**
 * Parse whatever the user pasted.
 *
 * Accepts a full account manifest (AWS or IBM), a bare AWS policy document, or
 * an array of policy documents — because those are the three things that
 * realistically end up in a clipboard.
 */
export function loadFromText(text: string, filename = 'pasted.json') {
  let raw: unknown
  try {
    raw = JSON.parse(text)
  } catch (err) {
    throw new Error(`That isn't valid JSON: ${(err as Error).message}`)
  }

  if (Array.isArray(raw)) {
    const docs = raw.filter(isPolicyDocument)
    if (docs.length === 0) {
      throw new Error('Expected an array of IAM policy documents, each with a "Statement" key.')
    }
    return finish(accountFromPolicyDocuments(docs, filename, text))
  }

  if (isPolicyDocument(raw)) {
    return finish(accountFromPolicyDocuments([raw], filename, text))
  }

  const manifest = raw as { entities?: unknown; policies?: unknown }
  if (!Array.isArray(manifest.entities) || !Array.isArray(manifest.policies)) {
    throw new Error(
      'Unrecognised shape. Paste an IAM policy document (an object with a "Statement" array), ' +
        'an array of them, or a full account manifest with "entities" and "policies".'
    )
  }

  return finish(normalize(raw, filename, text))
}

function finish(account: Account) {
  return { engine: buildEngine(account), account }
}
