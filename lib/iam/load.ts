/**
 * Loading accounts from disk. Server-only — imports node:fs.
 */

import { readFileSync, readdirSync } from 'node:fs'
import path from 'node:path'
import { buildEngine, IamEngine } from './engine'
import {
  loadAwsAccount,
  normalizeAwsPolicyDocument,
  RawAccountManifest,
  RawPolicyDocument,
} from './normalize/aws'
import { loadIbmAccount, RawIbmManifest } from './normalize/ibm'
import { Account, Policy } from './types'

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
      attachedTo: isResourcePolicy ? PASTED_RESOURCE : undefined,
      statements,
    }
  })

  const identityPolicies = policies.filter((p) => p.kind === 'identity').map((p) => p.id)

  return {
    provider: 'aws',
    id: PASTED_ACCOUNT,
    name: 'Pasted policy',
    trustedAccounts: [PASTED_ACCOUNT],
    entities: [
      {
        id: PASTED_PRINCIPAL,
        type: 'user',
        name: 'pasted-principal',
        attachedPolicies: identityPolicies,
      },
      {
        id: PASTED_RESOURCE,
        type: 'resource',
        name: 'pasted-resource',
        attachedPolicies: [],
      },
    ],
    policies,
  }
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
