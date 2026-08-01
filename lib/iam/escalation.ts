/**
 * Privilege escalation search.
 *
 * A dashboard tells you "Bob has read-only access". This tells you "Bob has
 * read-only access, and can reach the production database in three steps, here
 * is each step and the exact policy statement that permits it".
 *
 * The method is a fixpoint reachability search. We start with the identity the
 * attacker controls, repeatedly apply every known escalation technique to
 * whatever they control so far, and stop when nothing new is reachable. Every
 * edge added to the graph is backed by a real `allow` decision from the
 * deterministic engine, so a path is only ever reported if every single hop is
 * independently provable.
 *
 * Techniques are the documented AWS escalation methods. They are encoded as
 * data, not inferred by a model.
 */

import { IamEngine } from './engine'
import { Provider, Severity, SourceRef } from './types'

// ---------------------------------------------------------------------------
// Capabilities
// ---------------------------------------------------------------------------

export type Capability =
  /** We can act as this user or role */
  | { kind: 'identity'; id: string }
  /** We have joined this group, inheriting its policies */
  | { kind: 'group'; id: string }
  /** We can grant ourselves arbitrary permissions — game over */
  | { kind: 'admin' }

export function capKey(c: Capability): string {
  return c.kind === 'admin' ? 'admin' : `${c.kind}:${c.id}`
}

export function capLabel(c: Capability): string {
  if (c.kind === 'admin') return 'administrator access'
  return short(c.id)
}

export interface EscalationStep {
  technique: string
  techniqueName: string
  severity: Severity
  /** The identity that performs this step */
  actor: string
  /** What the step yields */
  gained: Capability
  /**
   * Capabilities this step required. Always includes the actor, and includes
   * any group the actor had to join first. Path reconstruction walks these, so
   * a multi-hop chain reports every hop rather than only the last one.
   */
  dependsOn: Capability[]
  /** Plain-language description of this single hop */
  narrative: string
  /** Statements that permit this hop */
  evidence: SourceRef[]
  reference: string
}

// ---------------------------------------------------------------------------
// Grants — an allow decision plus what it depended on
// ---------------------------------------------------------------------------

interface TechniqueContext {
  engine: IamEngine
  /** The principal the search started from */
  start: string
  /** Identities we currently control */
  identities: string[]
  /** Groups we have joined, on top of each identity's real membership */
  groups: string[]
}

/**
 * Joined groups apply to the starting user only.
 *
 * Group membership is a property of a user, not of a session. Once an attacker
 * assumes a role they act as that role with that role's policies alone — they
 * do not carry their own group memberships across. Leaking them would invent
 * permissions that do not exist, which is exactly the failure mode this whole
 * tool exists to avoid.
 */
function groupsFor(ctx: TechniqueContext, actor: string): string[] {
  return actor === ctx.start ? ctx.groups : []
}

interface Grant {
  evidence: SourceRef[]
  /** Gained groups that were necessary for this allow */
  deps: Capability[]
}

/**
 * Does `actor` have an allow for action/resource, and what did it depend on?
 *
 * We first check whether the actor could do it with no joined groups at all.
 * If so the grant is native and depends on nothing. Otherwise we find which
 * joined group unlocked it, so the escalation path can report "join this group
 * first" as its own step.
 */
function allows(
  ctx: TechniqueContext,
  actor: string,
  action: string,
  resource: string
): Grant | null {
  const groups = groupsFor(ctx, actor)
  const full = ctx.engine.can(actor, action, resource, {}, groups)
  if (full.decision !== 'allow') return null

  const native = ctx.engine.can(actor, action, resource, {}, [])
  if (native.decision === 'allow') {
    return { evidence: native.matched.map((s) => s.sourceRef), deps: [] }
  }

  // A joined group unlocked this. Find the minimal one so the path is honest
  // about which hop mattered.
  for (const group of groups) {
    const viaGroup = ctx.engine.can(actor, action, resource, {}, [group])
    if (viaGroup.decision === 'allow') {
      return {
        evidence: viaGroup.matched.map((s) => s.sourceRef),
        deps: [{ kind: 'group', id: group }],
      }
    }
  }

  // Needed a combination. Depend on all of them rather than guess.
  return {
    evidence: full.matched.map((s) => s.sourceRef),
    deps: groups.map((id) => ({ kind: 'group', id }) as Capability),
  }
}

function mergeGrants(
  actor: string,
  grants: Grant[]
): { evidence: SourceRef[]; dependsOn: Capability[] } {
  const dependsOn: Capability[] = [{ kind: 'identity', id: actor }]
  const seen = new Set<string>([capKey({ kind: 'identity', id: actor })])
  for (const g of grants) {
    for (const dep of g.deps) {
      const key = capKey(dep)
      if (seen.has(key)) continue
      seen.add(key)
      dependsOn.push(dep)
    }
  }
  return { evidence: dedupeRefs(grants.flatMap((g) => g.evidence)), dependsOn }
}

// ---------------------------------------------------------------------------
// Techniques
// ---------------------------------------------------------------------------

interface Technique {
  id: string
  name: string
  severity: Severity
  reference: string
  /**
   * Which provider's action vocabulary this technique speaks.
   *
   * This gating is load-bearing, not tidiness. An AWS policy using `NotAction`
   * or a bare `*` matches ANY action string — including IBM-format names like
   * `iam.policy.create`, which contain no colon and so are not excluded by
   * `NotAction: ["iam:*"]`. Without this filter an AWS "allow everything
   * except IAM" policy silently satisfies the IBM assign-access technique and
   * reports a privilege escalation that cannot happen.
   */
  provider: Provider
  expand(ctx: TechniqueContext): EscalationStep[]
}

const TECHNIQUES: Technique[] = [
  {
    id: 'add-user-to-group',
    provider: 'aws',
    name: 'Join a more privileged group',
    severity: 'high',
    reference: 'iam:AddUserToGroup',
    expand(ctx) {
      const steps: EscalationStep[] = []
      for (const actor of ctx.identities) {
        for (const group of ctx.engine.entities('group')) {
          const entity = ctx.engine.entity(actor)
          if (entity?.memberOf?.includes(group.id)) continue // already in it
          const grant = allows(ctx, actor, 'iam:AddUserToGroup', group.id)
          if (!grant) continue
          const { evidence, dependsOn } = mergeGrants(actor, [grant])
          steps.push({
            technique: this.id,
            techniqueName: this.name,
            severity: this.severity,
            actor,
            gained: { kind: 'group', id: group.id },
            dependsOn,
            narrative: `${nameOf(ctx.engine, actor)} can add any user to the ${group.name} group, including themselves, inheriting every policy attached to it.`,
            evidence,
            reference: this.reference,
          })
        }
      }
      return steps
    },
  },

  {
    id: 'modify-own-policy',
    provider: 'aws',
    name: 'Rewrite a policy attached to you',
    severity: 'critical',
    reference: 'iam:CreatePolicyVersion / iam:SetDefaultPolicyVersion',
    expand(ctx) {
      const steps: EscalationStep[] = []
      for (const actor of ctx.identities) {
        const entity = ctx.engine.entity(actor)
        if (!entity) continue

        // Policies reachable by this actor, remembering which joined group (if
        // any) brought each one in — that group becomes a path dependency.
        const owned: { policyId: string; via: Capability | null }[] = []
        for (const p of entity.attachedPolicies) owned.push({ policyId: p, via: null })
        for (const g of entity.memberOf ?? []) {
          for (const p of ctx.engine.entity(g)?.attachedPolicies ?? []) {
            owned.push({ policyId: p, via: null })
          }
        }
        for (const g of groupsFor(ctx, actor)) {
          for (const p of ctx.engine.entity(g)?.attachedPolicies ?? []) {
            owned.push({ policyId: p, via: { kind: 'group', id: g } })
          }
        }

        for (const { policyId, via } of owned) {
          for (const action of ['iam:CreatePolicyVersion', 'iam:SetDefaultPolicyVersion']) {
            const grant = allows(ctx, actor, action, policyId)
            if (!grant) continue
            const merged = mergeGrants(actor, [grant])
            const dependsOn = via
              ? dedupeCaps([...merged.dependsOn, via])
              : merged.dependsOn
            steps.push({
              technique: this.id,
              techniqueName: this.name,
              severity: this.severity,
              actor,
              gained: { kind: 'admin' },
              dependsOn,
              narrative: `${nameOf(ctx.engine, actor)} can publish a new version of ${short(policyId)}, a policy already attached to them, and set it to allow everything. That is full administrator access in one API call.`,
              evidence: merged.evidence,
              reference: this.reference,
            })
          }
        }
      }
      return steps
    },
  },

  {
    id: 'attach-policy-to-self',
    provider: 'aws',
    name: 'Attach an administrator policy to yourself',
    severity: 'critical',
    reference: 'iam:AttachUserPolicy / iam:PutUserPolicy',
    expand(ctx) {
      const steps: EscalationStep[] = []
      for (const actor of ctx.identities) {
        for (const action of [
          'iam:AttachUserPolicy',
          'iam:PutUserPolicy',
          'iam:AttachGroupPolicy',
          'iam:PutGroupPolicy',
        ]) {
          const grant = allows(ctx, actor, action, actor) ?? allows(ctx, actor, action, '*')
          if (!grant) continue
          const { evidence, dependsOn } = mergeGrants(actor, [grant])
          steps.push({
            technique: this.id,
            techniqueName: this.name,
            severity: this.severity,
            actor,
            gained: { kind: 'admin' },
            dependsOn,
            narrative: `${nameOf(ctx.engine, actor)} can attach an arbitrary policy to themselves via ${action}, so they can grant themselves administrator access at any time.`,
            evidence,
            reference: this.reference,
          })
          break
        }
      }
      return steps
    },
  },

  {
    id: 'pass-role-to-compute',
    provider: 'aws',
    name: 'Pass a role to a compute service you control',
    severity: 'critical',
    reference: 'iam:PassRole + ec2:RunInstances / lambda:CreateFunction',
    expand(ctx) {
      const vectors: { service: string; actions: string[]; label: string }[] = [
        { service: 'ec2.amazonaws.com', actions: ['ec2:RunInstances'], label: 'an EC2 instance' },
        {
          service: 'lambda.amazonaws.com',
          actions: ['lambda:CreateFunction', 'lambda:InvokeFunction'],
          label: 'a Lambda function',
        },
        { service: 'ecs-tasks.amazonaws.com', actions: ['ecs:RunTask'], label: 'an ECS task' },
      ]
      const steps: EscalationStep[] = []
      for (const actor of ctx.identities) {
        for (const role of ctx.engine.entities('role')) {
          if (role.id === actor) continue
          const passGrant = allows(ctx, actor, 'iam:PassRole', role.id)
          if (!passGrant) continue

          for (const vector of vectors) {
            if (!roleTrustsService(ctx.engine, role.id, vector.service)) continue

            const computeGrants: Grant[] = []
            let allPermitted = true
            for (const action of vector.actions) {
              const g = allows(ctx, actor, action, '*')
              if (!g) {
                allPermitted = false
                break
              }
              computeGrants.push(g)
            }
            if (!allPermitted) continue

            const { evidence, dependsOn } = mergeGrants(actor, [passGrant, ...computeGrants])
            steps.push({
              technique: this.id,
              techniqueName: this.name,
              severity: this.severity,
              actor,
              gained: { kind: 'identity', id: role.id },
              dependsOn,
              narrative: `${nameOf(ctx.engine, actor)} can launch ${vector.label} and attach the ${role.name} role to it. Any code running on it acts as ${role.name}, which hands them that role's permissions.`,
              evidence,
              reference: this.reference,
            })
            break
          }
        }
      }
      return steps
    },
  },

  {
    id: 'assume-role',
    provider: 'aws',
    name: 'Assume a role that trusts you',
    severity: 'medium',
    reference: 'sts:AssumeRole',
    expand(ctx) {
      const steps: EscalationStep[] = []
      for (const actor of ctx.identities) {
        for (const role of ctx.engine.entities('role')) {
          if (role.id === actor) continue
          const trust = ctx.engine.trustAllows(role.id, actor)
          if (trust.decision !== 'allow') continue
          const grant = allows(ctx, actor, 'sts:AssumeRole', role.id)
          if (!grant) continue
          const { evidence, dependsOn } = mergeGrants(actor, [grant])
          const wildcardTrust = trust.matched.some((s) =>
            s.principals?.some((p) => p.type === 'wildcard')
          )
          steps.push({
            technique: this.id,
            techniqueName: this.name,
            severity: wildcardTrust ? 'critical' : this.severity,
            actor,
            gained: { kind: 'identity', id: role.id },
            dependsOn,
            narrative: wildcardTrust
              ? `The ${role.name} role trusts every principal, so ${nameOf(ctx.engine, actor)} can assume it. So can anyone else who reaches this account.`
              : `${nameOf(ctx.engine, actor)} is trusted by the ${role.name} role and holds sts:AssumeRole, so they can switch into it directly.`,
            evidence: dedupeRefs([...evidence, ...trust.matched.map((s) => s.sourceRef)]),
            reference: this.reference,
          })
        }
      }
      return steps
    },
  },

  {
    id: 'rewrite-trust-policy',
    provider: 'aws',
    name: 'Rewrite a role trust policy to trust yourself',
    severity: 'critical',
    reference: 'iam:UpdateAssumeRolePolicy + sts:AssumeRole',
    expand(ctx) {
      const steps: EscalationStep[] = []
      for (const actor of ctx.identities) {
        for (const role of ctx.engine.entities('role')) {
          if (role.id === actor) continue
          const updateGrant = allows(ctx, actor, 'iam:UpdateAssumeRolePolicy', role.id)
          if (!updateGrant) continue
          const assumeGrant = allows(ctx, actor, 'sts:AssumeRole', role.id)
          if (!assumeGrant) continue
          const { evidence, dependsOn } = mergeGrants(actor, [updateGrant, assumeGrant])
          steps.push({
            technique: this.id,
            techniqueName: this.name,
            severity: this.severity,
            actor,
            gained: { kind: 'identity', id: role.id },
            dependsOn,
            narrative: `${nameOf(ctx.engine, actor)} can rewrite the ${role.name} role's trust policy to trust themselves, then assume it. The role's existing trust settings offer no protection.`,
            evidence,
            reference: this.reference,
          })
        }
      }
      return steps
    },
  },

  {
    id: 'steal-credentials',
    provider: 'aws',
    name: 'Mint credentials for another user',
    severity: 'critical',
    reference: 'iam:CreateAccessKey / iam:UpdateLoginProfile',
    expand(ctx) {
      const steps: EscalationStep[] = []
      for (const actor of ctx.identities) {
        for (const user of ctx.engine.entities('user')) {
          if (user.id === actor) continue
          for (const action of [
            'iam:CreateAccessKey',
            'iam:UpdateLoginProfile',
            'iam:CreateLoginProfile',
          ]) {
            const grant = allows(ctx, actor, action, user.id)
            if (!grant) continue
            const { evidence, dependsOn } = mergeGrants(actor, [grant])
            steps.push({
              technique: this.id,
              techniqueName: this.name,
              severity: this.severity,
              actor,
              gained: { kind: 'identity', id: user.id },
              dependsOn,
              narrative: `${nameOf(ctx.engine, actor)} can issue new credentials for ${user.name} via ${action}, letting them act as that user entirely.`,
              evidence,
              reference: this.reference,
            })
            break
          }
        }
      }
      return steps
    },
  },
]

// ---------------------------------------------------------------------------
// IBM Cloud techniques
//
// These check IBM-format action names (`service.resourceType.operation`), so
// they simply never match an AWS account and the AWS techniques never match an
// IBM one. Both lists can coexist without provider gating.
// ---------------------------------------------------------------------------

/** Does the actor hold this action anywhere, accounting for joined groups? */
function allowsAnywhere(ctx: TechniqueContext, actor: string, action: string): Grant | null {
  const groups = groupsFor(ctx, actor)
  const full = ctx.engine.canAnywhere(actor, action, groups)
  if (full.decision !== 'allow') return null

  const native = ctx.engine.canAnywhere(actor, action, [])
  if (native.decision === 'allow') {
    return { evidence: native.matched.map((s) => s.sourceRef), deps: [] }
  }
  for (const group of groups) {
    const viaGroup = ctx.engine.canAnywhere(actor, action, [group])
    if (viaGroup.decision === 'allow') {
      return {
        evidence: viaGroup.matched.map((s) => s.sourceRef),
        deps: [{ kind: 'group', id: group }],
      }
    }
  }
  return {
    evidence: full.matched.map((s) => s.sourceRef),
    deps: groups.map((id) => ({ kind: 'group', id }) as Capability),
  }
}

const IBM_TECHNIQUES: Technique[] = [
  {
    id: 'ibm-assign-access',
    provider: 'ibm',
    name: 'Grant yourself access (IBM Administrator role)',
    severity: 'critical',
    reference: 'iam.policy.create',
    expand(ctx) {
      const steps: EscalationStep[] = []
      for (const actor of ctx.identities) {
        const grant = allowsAnywhere(ctx, actor, 'iam.policy.create')
        if (!grant) continue
        const { evidence, dependsOn } = mergeGrants(actor, [grant])
        steps.push({
          technique: this.id,
          techniqueName: this.name,
          severity: this.severity,
          actor,
          gained: { kind: 'admin' },
          dependsOn,
          narrative: `${nameOf(ctx.engine, actor)} holds the Administrator platform role, which in IBM Cloud includes the right to assign access to others. They can write themselves a policy granting anything. "Administrator" reads like an ordinary admin tier, but it is a self-service escalation to full control.`,
          evidence,
          reference: this.reference,
        })
      }
      return steps
    },
  },

  {
    id: 'ibm-join-access-group',
    provider: 'ibm',
    name: 'Add yourself to an access group',
    severity: 'high',
    reference: 'iam-groups.*.update',
    expand(ctx) {
      const steps: EscalationStep[] = []
      for (const actor of ctx.identities) {
        const grant =
          allowsAnywhere(ctx, actor, 'iam-groups.groups.update') ??
          allowsAnywhere(ctx, actor, 'iam-groups.members.create')
        if (!grant) continue

        for (const group of ctx.engine.entities('group')) {
          const entity = ctx.engine.entity(actor)
          if (entity?.memberOf?.includes(group.id)) continue
          const { evidence, dependsOn } = mergeGrants(actor, [grant])
          steps.push({
            technique: this.id,
            techniqueName: this.name,
            severity: this.severity,
            actor,
            gained: { kind: 'group', id: group.id },
            dependsOn,
            narrative: `${nameOf(ctx.engine, actor)} can manage access group membership, so they can add themselves to ${group.name} and inherit every policy attached to it.`,
            evidence,
            reference: this.reference,
          })
        }
      }
      return steps
    },
  },

  {
    id: 'ibm-create-service-id',
    provider: 'ibm',
    name: 'Create a service ID and act as it',
    severity: 'critical',
    reference: 'iam-identity.serviceid.create',
    expand(ctx) {
      const steps: EscalationStep[] = []
      for (const actor of ctx.identities) {
        const grant = allowsAnywhere(ctx, actor, 'iam-identity.serviceid.create')
        if (!grant) continue
        for (const svc of ctx.engine.entities('service')) {
          if (svc.id === actor) continue
          const { evidence, dependsOn } = mergeGrants(actor, [grant])
          steps.push({
            technique: this.id,
            techniqueName: this.name,
            severity: this.severity,
            actor,
            gained: { kind: 'identity', id: svc.id },
            dependsOn,
            narrative: `${nameOf(ctx.engine, actor)} can create service IDs and issue API keys for them, letting them operate as ${svc.name} with that identity's permissions.`,
            evidence,
            reference: this.reference,
          })
        }
      }
      return steps
    },
  },
]

function roleTrustsService(engine: IamEngine, roleId: string, service: string): boolean {
  for (const stmt of engine.trustStatements(roleId)) {
    if (stmt.effect !== 'Allow') continue
    if (!stmt.principals) continue
    if (stmt.principals.some((p) => p.type === 'service' && (p.id === service || p.id === '*'))) {
      return true
    }
  }
  return false
}

/**
 * Every technique, both providers. An AWS technique's action names never match
 * an IBM policy and vice versa, so running the full list against either
 * account is correct as well as simpler than gating on provider.
 */
const ALL_TECHNIQUES: Technique[] = [...TECHNIQUES, ...IBM_TECHNIQUES]

/** Only the techniques whose action vocabulary matches this account. */
function techniquesFor(provider: Provider): Technique[] {
  return ALL_TECHNIQUES.filter((t) => t.provider === provider)
}

/**
 * Display name for a principal. AWS ARNs end in something human-readable, but
 * an IBM `IBMid-550000BBBB` does not — so prefer the entity's own name and
 * fall back to trimming the identifier.
 */
function nameOf(engine: IamEngine, id: string): string {
  return engine.entity(id)?.name ?? short(id)
}

export function short(arn: string): string {
  const slash = arn.lastIndexOf('/')
  if (slash !== -1) return arn.slice(slash + 1)
  const colon = arn.lastIndexOf(':')
  return colon === -1 ? arn : arn.slice(colon + 1)
}

function dedupeRefs(refs: SourceRef[]): SourceRef[] {
  const seen = new Set<string>()
  const out: SourceRef[] = []
  for (const r of refs) {
    const key = `${r.file}${r.pointer}`
    if (seen.has(key)) continue
    seen.add(key)
    out.push(r)
  }
  return out
}

function dedupeCaps(caps: Capability[]): Capability[] {
  const seen = new Set<string>()
  const out: Capability[] = []
  for (const c of caps) {
    const key = capKey(c)
    if (seen.has(key)) continue
    seen.add(key)
    out.push(c)
  }
  return out
}

// ---------------------------------------------------------------------------
// The search
// ---------------------------------------------------------------------------

export interface ReachabilityResult {
  start: string
  capabilities: Capability[]
  /** capKey -> the step that first produced it */
  producedBy: Map<string, EscalationStep>
  reachesAdmin: boolean
}

/**
 * Everything `principalId` can eventually control. Runs to a fixpoint, so a
 * capability unlocked on round 3 feeds every technique again on round 4.
 */
export function reachableCapabilities(
  engine: IamEngine,
  principalId: string,
  maxRounds = 8
): ReachabilityResult {
  const caps = new Map<string, Capability>()
  const producedBy = new Map<string, EscalationStep>()
  const startCap: Capability = { kind: 'identity', id: principalId }
  caps.set(capKey(startCap), startCap)

  for (let round = 0; round < maxRounds; round++) {
    const identities = [...caps.values()]
      .filter((c): c is { kind: 'identity'; id: string } => c.kind === 'identity')
      .map((c) => c.id)
    const groups = [...caps.values()]
      .filter((c): c is { kind: 'group'; id: string } => c.kind === 'group')
      .map((c) => c.id)

    const ctx: TechniqueContext = { engine, start: principalId, identities, groups }
    let changed = false

    for (const technique of techniquesFor(engine.account.provider)) {
      for (const step of technique.expand(ctx)) {
        const key = capKey(step.gained)
        if (caps.has(key)) continue
        caps.set(key, step.gained)
        producedBy.set(key, step)
        changed = true
      }
    }

    if (!changed) break
  }

  return {
    start: principalId,
    capabilities: [...caps.values()],
    producedBy,
    reachesAdmin: caps.has('admin'),
  }
}

export interface EscalationPath {
  start: string
  target: Capability
  steps: EscalationStep[]
}

/**
 * Reconstruct how a set of capabilities was reached.
 *
 * Walks the dependency DAG depth-first from each root, so prerequisites are
 * emitted before the steps that need them. This is what makes a multi-hop
 * chain report every hop: the "pass a role" step depends on the group the
 * actor had to join, so the group-join step is pulled in ahead of it.
 */
export function pathToAll(
  reach: ReachabilityResult,
  targets: Capability[]
): EscalationPath | null {
  const steps: EscalationStep[] = []
  const emitted = new Set<string>()
  const inProgress = new Set<string>()
  const startKey = capKey({ kind: 'identity', id: reach.start })

  const visit = (key: string): boolean => {
    if (key === startKey) return true
    if (emitted.has(key)) return true
    if (inProgress.has(key)) return true // defensive: never loop
    inProgress.add(key)

    const step = reach.producedBy.get(key)
    if (!step) return false

    for (const dep of step.dependsOn) {
      if (!visit(capKey(dep))) return false
    }

    inProgress.delete(key)
    emitted.add(key)
    steps.push(step)
    return true
  }

  for (const target of targets) {
    if (!visit(capKey(target))) return null
  }

  return { start: reach.start, target: targets[targets.length - 1], steps }
}

export function pathTo(
  reach: ReachabilityResult,
  target: Capability
): EscalationPath | null {
  return pathToAll(reach, [target])
}

export interface EscalationRoute {
  principal: string
  /** Identity that ultimately performs the action */
  via: string
  steps: EscalationStep[]
  /** Statements permitting the final action itself */
  finalEvidence: SourceRef[]
}

/**
 * Every distinct way `principalId` can reach `action` on `resource` by
 * escalating first, shortest route first.
 *
 * This is the question the brief is really asking with "who can delete
 * production databases". The direct answer is usually short and reassuring.
 * This one is neither.
 */
export function escalationRoutes(
  engine: IamEngine,
  principalId: string,
  action: string,
  resource: string
): EscalationRoute[] {
  // Anything they already hold outright is direct access, not escalation.
  if (engine.can(principalId, action, resource).decision === 'allow') return []

  const reach = reachableCapabilities(engine, principalId)
  const gainedGroups = reach.capabilities
    .filter((c): c is { kind: 'group'; id: string } => c.kind === 'group')
    .map((c) => c.id)

  const routes: EscalationRoute[] = []

  // Full admin trivially permits everything.
  if (reach.reachesAdmin) {
    const path = pathTo(reach, { kind: 'admin' })
    if (path) {
      routes.push({
        principal: principalId,
        via: 'administrator access',
        steps: path.steps,
        finalEvidence: [],
      })
    }
  }

  for (const cap of reach.capabilities) {
    if (cap.kind !== 'identity') continue

    const ctx: TechniqueContext = {
      engine,
      start: principalId,
      identities: [cap.id],
      groups: gainedGroups,
    }
    const grant = allows(ctx, cap.id, action, resource)
    if (!grant) continue

    // Reaching the action needs the acting identity plus any group that
    // unlocked it. Both go into the path so no hop is silently dropped.
    const roots: Capability[] = dedupeCaps([cap, ...grant.deps])
    const path = pathToAll(reach, roots)
    if (!path || path.steps.length === 0) continue

    routes.push({
      principal: principalId,
      via: cap.id,
      steps: path.steps,
      finalEvidence: grant.evidence,
    })
  }

  return routes.sort((a, b) => a.steps.length - b.steps.length)
}

/**
 * The headline query: every principal that can reach `action` on `resource`,
 * split into those who hold it outright and those who can take it.
 */
export function whoCanReach(
  engine: IamEngine,
  action: string,
  resource: string
): {
  direct: { principal: string; evidence: SourceRef[] }[]
  indirect: { principal: string; routes: EscalationRoute[] }[]
} {
  const direct: { principal: string; evidence: SourceRef[] }[] = []
  const indirect: { principal: string; routes: EscalationRoute[] }[] = []

  for (const principal of engine.principals()) {
    const result = engine.can(principal.id, action, resource)
    if (result.decision === 'allow') {
      direct.push({
        principal: principal.id,
        evidence: result.matched.map((s) => s.sourceRef),
      })
      continue
    }
    const routes = escalationRoutes(engine, principal.id, action, resource)
    if (routes.length > 0) indirect.push({ principal: principal.id, routes })
  }

  return { direct, indirect }
}
