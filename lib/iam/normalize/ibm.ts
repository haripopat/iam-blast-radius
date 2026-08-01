/**
 * IBM Cloud IAM -> normalised model.
 *
 * IBM models access very differently from AWS, and the difference is the whole
 * reason this file exists rather than a find-and-replace on the AWS one:
 *
 *  - AWS policies name **actions** directly (`s3:GetObject`). IBM policies
 *    name **roles** (`Viewer`, `Editor`, `Administrator`), and the actions
 *    each role covers are defined by the platform. So normalising means
 *    expanding a role into the action set it implies.
 *  - AWS scopes with an ARN string. IBM scopes with an **attribute set**
 *    (`serviceName`, `resourceGroupId`, `serviceInstance`, …), where an
 *    omitted attribute means "any". A policy with only `serviceName` set
 *    therefore covers every instance of that service — easy to under-read.
 *  - IBM's **Administrator** platform role includes the right to assign
 *    access to other people. That is a privilege-escalation primitive baked
 *    into a role name that reads like an ordinary admin tier, and it is the
 *    single most important thing for this tool to model correctly.
 *
 * Action naming follows IBM's own `<service>.<resourceType>.<operation>`
 * convention rather than being coerced into AWS syntax, so nothing here
 * pretends to be something it isn't.
 */

import { Account, Entity, Policy, Statement } from '../types'

// ---------------------------------------------------------------------------
// Roles
// ---------------------------------------------------------------------------

/**
 * What each IBM role expands to, as action globs scoped to a service.
 * `{svc}` is substituted with the policy's target service (or `*`).
 *
 * Platform roles govern the resource itself and access to it; service roles
 * govern the data inside it. A policy can carry both.
 */
const ROLE_ACTIONS: Record<string, string[]> = {
  // Platform roles
  Viewer: ['{svc}.*.get', '{svc}.*.list'],
  Operator: ['{svc}.*.get', '{svc}.*.list', '{svc}.*.operate'],
  Editor: [
    '{svc}.*.get',
    '{svc}.*.list',
    '{svc}.*.operate',
    '{svc}.*.create',
    '{svc}.*.update',
    '{svc}.*.delete',
  ],
  // Administrator is Editor PLUS the right to grant access to others.
  // `iam.policy.create` is what makes this an escalation primitive.
  Administrator: ['{svc}.*.*', 'iam.policy.create', 'iam.policy.update'],

  // Service roles
  Reader: ['{svc}.data.read'],
  Writer: ['{svc}.data.read', '{svc}.data.write'],
  Manager: ['{svc}.data.read', '{svc}.data.write', '{svc}.data.manage'],
}

export const PLATFORM_ROLES = ['Viewer', 'Operator', 'Editor', 'Administrator']
export const SERVICE_ROLES = ['Reader', 'Writer', 'Manager']

/** `crn:v1:bluemix:public:iam::::role:Editor` -> `Editor`; passes bare names through. */
export function roleName(roleId: string): string {
  if (!roleId.startsWith('crn:')) return roleId
  const idx = roleId.lastIndexOf(':role:')
  return idx === -1 ? roleId : roleId.slice(idx + ':role:'.length)
}

export function expandRole(role: string, service: string): string[] {
  const actions = ROLE_ACTIONS[roleName(role)]
  if (!actions) return []
  return actions.map((a) => a.replace('{svc}', service || '*'))
}

// ---------------------------------------------------------------------------
// Raw manifest shape
// ---------------------------------------------------------------------------

interface RawAttribute {
  name: string
  value: string
  operator?: string
}

interface RawSubject {
  attributes: RawAttribute[]
}

interface RawResource {
  attributes: RawAttribute[]
}

export interface RawIbmPolicy {
  id: string
  /** `access` (grant access) or `authorization` (service-to-service) */
  type?: string
  description?: string
  subjects: RawSubject[]
  roles: { role_id: string }[]
  resources: RawResource[]
}

export interface RawIbmManifest {
  provider: 'ibm'
  /** IBM account id */
  id: string
  name: string
  trustedAccounts?: string[]
  entities: {
    id: string
    type: Entity['type']
    name: string
    memberOf?: string[]
    tags?: Record<string, string>
  }[]
  policies: RawIbmPolicy[]
}

function attr(attrs: RawAttribute[], name: string): string | undefined {
  return attrs.find((a) => a.name === name)?.value
}

/**
 * Build the resource identifier a policy targets.
 *
 * If the policy names a specific instance we use its CRN. Otherwise we build a
 * glob from the attributes that ARE set — an unset attribute means "any", so
 * a policy scoped only by `serviceName` becomes `crn:...:<service>:*`, which
 * correctly matches every instance of that service.
 */
function resourceTarget(resource: RawResource, accountId: string): string {
  const a = resource.attributes
  const instance = attr(a, 'serviceInstance') ?? attr(a, 'resource')
  if (instance?.startsWith('crn:')) return instance

  const service = attr(a, 'serviceName') ?? '*'
  const region = attr(a, 'region') ?? '*'
  const account = attr(a, 'accountId') ?? accountId
  const instanceSeg = instance ?? '*'
  const resourceType = attr(a, 'resourceType') ?? '*'

  return `crn:v1:bluemix:public:${service}:${region}:a/${account}:${instanceSeg}:${resourceType}:*`
}

/** IBM identifies subjects by attribute, and the attribute name is the type. */
function subjectId(subject: RawSubject): string | null {
  const a = subject.attributes
  return (
    attr(a, 'iam_id') ??
    attr(a, 'access_group_id') ??
    attr(a, 'service_id') ??
    attr(a, 'profile_id') ??
    null
  )
}

// ---------------------------------------------------------------------------
// Normalisation
// ---------------------------------------------------------------------------

export function loadIbmAccount(
  manifest: RawIbmManifest,
  file: string,
  rawText?: string
): Account {
  const policies: Policy[] = []

  manifest.policies.forEach((raw, policyIndex) => {
    const statements: Statement[] = []

    raw.resources.forEach((resource, resourceIndex) => {
      const service = attr(resource.attributes, 'serviceName') ?? '*'
      const target = resourceTarget(resource, manifest.id)

      const actions = raw.roles.flatMap((r) => expandRole(r.role_id, service))
      if (actions.length === 0) return

      statements.push({
        id: `${raw.id}#${resourceIndex}`,
        sourceRef: {
          file,
          pointer: `/policies/${policyIndex}/resources/${resourceIndex}`,
          snippet: JSON.stringify(
            {
              id: raw.id,
              description: raw.description,
              roles: raw.roles.map((r) => roleName(r.role_id)),
              subjects: raw.subjects.map((s) => subjectId(s)),
              resource: resource.attributes,
            },
            null,
            2
          ),
          line: findLine(rawText, raw.id),
        },
        effect: 'Allow', // IBM access policies only grant; there is no Deny.
        actions,
        resources: [target],
        conditions: [],
      })
    })

    if (statements.length === 0) return

    policies.push({
      id: raw.id,
      name: raw.description ?? raw.id,
      provider: 'ibm',
      kind: 'identity',
      statements,
    })
  })

  // A policy's subjects are what it is attached to. Build that mapping so the
  // engine's existing attachment model works unchanged.
  const attachments = new Map<string, string[]>()
  manifest.policies.forEach((raw) => {
    for (const subject of raw.subjects) {
      const id = subjectId(subject)
      if (!id) continue
      const list = attachments.get(id) ?? []
      list.push(raw.id)
      attachments.set(id, list)
    }
  })

  const entities: Entity[] = manifest.entities.map((e) => ({
    id: e.id,
    type: e.type,
    name: e.name,
    attachedPolicies: attachments.get(e.id) ?? [],
    memberOf: e.memberOf,
    tags: e.tags,
  }))

  return {
    provider: 'ibm',
    id: manifest.id,
    name: manifest.name,
    trustedAccounts: manifest.trustedAccounts ?? [manifest.id],
    entities,
    policies,
  }
}

function findLine(rawText: string | undefined, needle: string | undefined): number | undefined {
  if (!rawText || !needle) return undefined
  const idx = rawText.indexOf(`"${needle}"`)
  if (idx === -1) return undefined
  return rawText.slice(0, idx).split('\n').length
}
