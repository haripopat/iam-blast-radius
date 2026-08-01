/**
 * Deterministic risk rules.
 *
 * Each rule is a pure function over the account that returns `Finding`s. No
 * model is involved in deciding whether something is a risk — a rule either
 * structurally matches or it does not, and every finding carries the exact
 * statements that triggered it.
 *
 * `confidence` distinguishes the two honest categories:
 *   - `certain`  — the structure itself is the problem (a wildcard principal
 *                  is a wildcard principal, there is nothing to interpret)
 *   - `probable` — we inferred intent, e.g. "this resource looks like
 *                  production because it is tagged that way"
 * The UI shows the difference. Overstating confidence is how security tools
 * lose the trust of the people who have to action their output.
 */

import { IamEngine } from '../engine'
import { escalationRoutes, reachableCapabilities, short } from '../escalation'
import { Finding, Policy, Severity, Statement } from '../types'
import { parseCrn } from '../match'

interface Rule {
  id: string
  run(engine: IamEngine): Finding[]
}

function statementsOf(engine: IamEngine, kind?: Policy['kind']) {
  const out: { policy: Policy; statement: Statement }[] = []
  for (const policy of engine.account.policies) {
    if (kind && policy.kind !== kind) continue
    for (const statement of policy.statements) out.push({ policy, statement })
  }
  return out
}

/**
 * A statement that already allows everything on everything is reported once by
 * `wildcard-action-resource`. The narrower rules skip it, otherwise a single
 * admin policy produces one finding per specific pattern it happens to contain
 * and buries the findings that actually need triage.
 */
function isFullWildcard(statement: Statement): boolean {
  return statement.actions.includes('*') && statement.resources.includes('*')
}

/** Which identities end up holding a given policy, for blast-radius wording. */
function holdersOf(engine: IamEngine, policyId: string): string[] {
  const holders: string[] = []
  for (const entity of engine.entities()) {
    if (entity.attachedPolicies.includes(policyId)) {
      if (entity.type === 'group') {
        for (const user of engine.entities('user')) {
          if (user.memberOf?.includes(entity.id)) holders.push(user.id)
        }
      } else {
        holders.push(entity.id)
      }
    }
  }
  return [...new Set(holders)]
}

const RULES: Rule[] = [
  // -------------------------------------------------------------------------
  {
    id: 'wildcard-action-resource',
    run(engine) {
      const findings: Finding[] = []
      for (const { policy, statement } of statementsOf(engine, 'identity')) {
        if (statement.effect !== 'Allow') continue
        const wildAction = statement.actions.includes('*')
        const wildResource = statement.resources.includes('*')
        if (!wildAction || !wildResource) continue

        const holders = holdersOf(engine, policy.id)
        findings.push({
          id: `wildcard-action-resource:${statement.id}`,
          rule: this.id,
          severity: 'critical',
          title: `${policy.name} grants every action on every resource`,
          description:
            `The statement allows "*" on "*", which is unrestricted administrator access to the ` +
            `entire account. ${holders.length > 0 ? `It is held by ${holders.map(short).join(', ')}.` : 'It is not currently attached to anyone, but remains available to attach.'}`,
          remediation:
            'Replace the wildcards with the specific actions and resource ARNs actually required. ' +
            'If this is a genuine break-glass role, gate it behind an MFA condition and alert on every use.',
          principals: holders,
          evidence: [statement.sourceRef],
          confidence: 'certain',
        })
      }
      return findings
    },
  },

  // -------------------------------------------------------------------------
  {
    id: 'wildcard-principal-trust',
    run(engine) {
      const findings: Finding[] = []
      for (const { policy, statement } of statementsOf(engine, 'trust')) {
        if (statement.effect !== 'Allow') continue
        if (!statement.principals?.some((p) => p.type === 'wildcard')) continue

        const hasGuard = statement.conditions.length > 0
        findings.push({
          id: `wildcard-principal-trust:${statement.id}`,
          rule: this.id,
          severity: hasGuard ? 'high' : 'critical',
          title: `${policy.name} lets any AWS principal assume the role`,
          description:
            `The trust policy names "*" as its principal${hasGuard ? ', guarded only by a condition' : ' with no conditions at all'}. ` +
            `${hasGuard ? 'The condition is the only thing standing between an arbitrary AWS account and this role.' : 'Any AWS account on earth can assume this role and inherit everything it can do.'}`,
          remediation:
            'Name the exact accounts, roles, or federated providers that should be trusted. ' +
            'If this is for a third-party integration, require an sts:ExternalId condition as well.',
          principals: policy.attachedTo ? [policy.attachedTo] : [],
          evidence: [statement.sourceRef],
          confidence: 'certain',
        })
      }
      return findings
    },
  },

  // -------------------------------------------------------------------------
  {
    id: 'public-resource-policy',
    run(engine) {
      const findings: Finding[] = []
      for (const { policy, statement } of statementsOf(engine, 'resource')) {
        if (statement.effect !== 'Allow') continue
        if (!statement.principals?.some((p) => p.type === 'wildcard')) continue
        if (statement.conditions.length > 0) continue

        const target = policy.attachedTo ?? 'the resource'
        const entity = policy.attachedTo ? engine.entity(policy.attachedTo) : undefined
        const sensitive = entity?.tags?.env === 'production' || !!entity?.tags?.data

        findings.push({
          id: `public-resource-policy:${statement.id}`,
          rule: this.id,
          severity: sensitive ? 'critical' : 'high',
          title: `${short(target)} is readable by anyone`,
          description:
            `The resource policy allows ${statement.actions.join(', ')} to principal "*" with no conditions, ` +
            `which means the public internet.` +
            (sensitive
              ? ` This resource is tagged ${JSON.stringify(entity?.tags)}, so this is likely an exposure of sensitive data.`
              : ''),
          remediation:
            'Restrict the principal to the specific accounts or roles that need access. ' +
            'If public read really is intended, serve it through a CDN origin-access identity rather than a public bucket policy.',
          principals: policy.attachedTo ? [policy.attachedTo] : [],
          evidence: [statement.sourceRef],
          confidence: sensitive ? 'probable' : 'certain',
        })
      }
      return findings
    },
  },

  // -------------------------------------------------------------------------
  {
    id: 'cross-account-trust',
    run(engine) {
      const findings: Finding[] = []
      for (const { policy, statement } of statementsOf(engine, 'trust')) {
        if (statement.effect !== 'Allow') continue
        for (const principal of statement.principals ?? []) {
          if (principal.type === 'wildcard') continue // covered by its own rule
          const account = principal.id.split(':')[4]
          if (!account || engine.isTrustedAccount(account)) continue

          const hasExternalId = statement.conditions.some((c) => c.key === 'sts:ExternalId')
          findings.push({
            id: `cross-account-trust:${statement.id}:${principal.id}`,
            rule: this.id,
            severity: hasExternalId ? 'medium' : 'high',
            title: `${policy.name} trusts external account ${account}`,
            description:
              `This role can be assumed by an account outside the organisation` +
              (hasExternalId
                ? ', though an sts:ExternalId condition is present.'
                : ', with no sts:ExternalId condition. This is the classic confused-deputy setup: if the third party is breached, or simply guesses the role ARN, they reach straight into this account.'),
            remediation: hasExternalId
              ? 'Confirm the external ID is a secret, is unique per customer, and is rotated.'
              : 'Add an sts:ExternalId condition with a secret unique to this integration, and narrow the trusted principal from the account root to a specific role.',
            principals: policy.attachedTo ? [policy.attachedTo] : [],
            evidence: [statement.sourceRef],
            confidence: 'certain',
          })
        }
      }
      return findings
    },
  },

  // -------------------------------------------------------------------------
  {
    id: 'not-action-inversion',
    run(engine) {
      const findings: Finding[] = []
      for (const { policy, statement } of statementsOf(engine)) {
        if (statement.effect !== 'Allow') continue
        if (!statement.notActions || statement.notActions.length === 0) continue

        const holders = holdersOf(engine, policy.id)
        findings.push({
          id: `not-action-inversion:${statement.id}`,
          rule: this.id,
          severity: 'high',
          title: `${policy.name} allows everything except a short list`,
          description:
            `The statement uses NotAction, so it grants every action in AWS except ` +
            `${statement.notActions.join(', ')}. This is almost always a mistake: it reads like a restriction ` +
            `but is actually one of the broadest grants you can write, and it silently widens every time AWS ships a new service. ` +
            `${holders.length > 0 ? `Held by ${holders.map(short).join(', ')}.` : ''}`,
          remediation:
            'Rewrite as an explicit Allow listing the actions that are genuinely needed. ' +
            'If the intent was to block those actions, use a separate statement with Effect: Deny and Action, not Allow with NotAction.',
          principals: holders,
          evidence: [statement.sourceRef],
          confidence: 'certain',
        })
      }
      return findings
    },
  },

  // -------------------------------------------------------------------------
  {
    id: 'passrole-wildcard',
    run(engine) {
      const findings: Finding[] = []
      for (const { policy, statement } of statementsOf(engine, 'identity')) {
        if (statement.effect !== 'Allow') continue
        if (isFullWildcard(statement)) continue
        const grantsPassRole = statement.actions.some(
          (a) => a === '*' || a.toLowerCase() === 'iam:passrole'
        )
        if (!grantsPassRole) continue
        if (!statement.resources.includes('*')) continue

        const holders = holdersOf(engine, policy.id)
        findings.push({
          id: `passrole-wildcard:${statement.id}`,
          rule: this.id,
          severity: 'high',
          title: `${policy.name} allows iam:PassRole on every role`,
          description:
            `Holders can hand any role in the account to a compute service they control, then run code as that role. ` +
            `Combined with a permission like ec2:RunInstances or lambda:CreateFunction this is a full privilege escalation, ` +
            `and it is invisible to any review that looks at permissions one at a time. ` +
            `${holders.length > 0 ? `Held by ${holders.map(short).join(', ')}.` : ''}`,
          remediation:
            'Scope the Resource to the specific role ARNs that may be passed, and add an iam:PassedToService ' +
            'condition so the role can only be handed to the intended service.',
          principals: holders,
          evidence: [statement.sourceRef],
          confidence: 'certain',
        })
      }
      return findings
    },
  },

  // -------------------------------------------------------------------------
  {
    id: 'self-service-group-membership',
    run(engine) {
      const findings: Finding[] = []
      for (const { policy, statement } of statementsOf(engine, 'identity')) {
        if (statement.effect !== 'Allow') continue
        if (isFullWildcard(statement)) continue
        if (!statement.actions.some((a) => a === '*' || a.toLowerCase() === 'iam:addusertogroup')) {
          continue
        }
        if (!statement.resources.includes('*')) continue

        const holders = holdersOf(engine, policy.id)
        findings.push({
          id: `self-service-group-membership:${statement.id}`,
          rule: this.id,
          severity: 'critical',
          title: `${policy.name} lets holders join any group`,
          description:
            `iam:AddUserToGroup on "*" means holders can add themselves to any group in the account, ` +
            `inheriting whatever that group can do. Every permission boundary built with groups is void for these users. ` +
            `${holders.length > 0 ? `Held by ${holders.map(short).join(', ')}.` : ''}`,
          remediation:
            'Scope the Resource to the specific groups that self-service should cover, and exclude any group ' +
            'with privileged policies attached. Better still, move group changes behind an approval workflow.',
          principals: holders,
          evidence: [statement.sourceRef],
          confidence: 'certain',
        })
      }
      return findings
    },
  },

  // -------------------------------------------------------------------------
  {
    id: 'privileged-role-without-mfa',
    run(engine) {
      const findings: Finding[] = []
      for (const role of engine.entities('role')) {
        const isAdmin =
          engine.can(role.id, 'iam:CreateUser', '*').decision === 'allow' &&
          engine.can(role.id, 'ec2:TerminateInstances', '*').decision === 'allow'
        if (!isAdmin) continue

        const trust = engine.trustStatements(role.id)
        const hasMfa = trust.some((s) =>
          s.conditions.some((c) => c.key === 'aws:MultiFactorAuthPresent')
        )
        if (hasMfa) continue
        // A role assumed by a service cannot present MFA; only flag human paths.
        const humanAssumable = trust.some((s) =>
          s.principals?.some((p) => p.type !== 'service')
        )
        if (!humanAssumable) continue

        findings.push({
          id: `privileged-role-without-mfa:${role.id}`,
          rule: this.id,
          severity: 'medium',
          title: `${role.name} has administrator permissions and no MFA requirement`,
          description:
            `This role can be assumed by a human principal without proving multi-factor authentication, ` +
            `yet it holds broad administrative permissions. A single stolen credential is enough to use it.`,
          remediation:
            'Add a Bool condition on aws:MultiFactorAuthPresent to the trust policy, and alert on every assumption of this role.',
          principals: [role.id],
          evidence: trust.map((s) => s.sourceRef),
          confidence: 'certain',
        })
      }
      return findings
    },
  },

  // -------------------------------------------------------------------------
  // IBM Cloud. These key off the normalised shape rather than the provider
  // flag, so they simply never match an AWS statement.
  // -------------------------------------------------------------------------
  {
    id: 'ibm-account-wide-policy',
    run(engine) {
      const findings: Finding[] = []
      for (const { policy, statement } of statementsOf(engine)) {
        if (policy.provider !== 'ibm') continue
        if (statement.effect !== 'Allow') continue
        // No serviceName attribute normalises to a `*` service segment, which
        // means the policy covers every IAM-enabled service in the account.
        if (statement.resources.every((r) => parseCrn(r)?.service !== '*')) continue

        const holders = holdersOf(engine, policy.id)
        findings.push({
          id: `ibm-account-wide-policy:${statement.id}`,
          rule: this.id,
          severity: 'high',
          title: `${policy.name} applies to every service in the account`,
          description:
            `This policy sets no serviceName attribute. In IBM Cloud an omitted attribute means "any", ` +
            `so rather than scoping to one service it grants these roles across every IAM-enabled service ` +
            `in the account — including ones added in future. This is easy to misread as narrow. ` +
            `${holders.length > 0 ? `Held by ${holders.map((h) => engine.entity(h)?.name ?? short(h)).join(', ')}.` : ''}`,
          remediation:
            'Add a serviceName attribute to scope the policy, and a serviceInstance attribute if only one instance is intended. ' +
            'Grant per-service policies rather than one account-wide policy.',
          principals: holders,
          evidence: [statement.sourceRef],
          confidence: 'certain',
        })
      }
      return findings
    },
  },

  {
    id: 'ibm-assign-access-role',
    run(engine) {
      const findings: Finding[] = []
      for (const { policy, statement } of statementsOf(engine)) {
        if (policy.provider !== 'ibm') continue
        if (statement.effect !== 'Allow') continue
        // The Administrator platform role is the only one that expands to
        // include policy creation.
        if (!statement.actions.includes('iam.policy.create')) continue

        const holders = holdersOf(engine, policy.id)
        findings.push({
          id: `ibm-assign-access-role:${statement.id}`,
          rule: this.id,
          severity: 'critical',
          title: `${policy.name} grants the Administrator role, which includes assigning access`,
          description:
            `In IBM Cloud the Administrator platform role carries the right to create access policies, ` +
            `not just to manage the resource. Anyone holding it can write themselves a policy granting ` +
            `anything else in the account, so this is effectively unbounded access however narrowly the ` +
            `rest of the policy is scoped. ` +
            `${holders.length > 0 ? `Held by ${holders.map((h) => engine.entity(h)?.name ?? short(h)).join(', ')}.` : ''}`,
          remediation:
            'Use Editor for people who need to manage the resource but not delegate access. ' +
            'Reserve Administrator for a small, audited group, and alert on iam.policy.create.',
          principals: holders,
          evidence: [statement.sourceRef],
          confidence: 'certain',
        })
      }
      return findings
    },
  },

  // -------------------------------------------------------------------------
  // The differentiator: escalation paths promoted into findings.
  // -------------------------------------------------------------------------
  {
    id: 'privilege-escalation-path',
    run(engine) {
      const findings: Finding[] = []
      for (const principal of engine.principals()) {
        const reach = reachableCapabilities(engine, principal.id)
        if (reach.reachesAdmin) {
          const routes = escalationRoutes(engine, principal.id, 'iam:CreateUser', '*')
          const best = routes[0]
          if (!best) continue
          findings.push({
            id: `privilege-escalation-path:${principal.id}:admin`,
            rule: this.id,
            severity: 'critical',
            title: `${principal.name} can escalate to full administrator`,
            description:
              `${principal.name} does not hold administrator access, but can obtain it in ` +
              `${best.steps.length} step${best.steps.length === 1 ? '' : 's'}: ` +
              best.steps.map((s, i) => `(${i + 1}) ${s.narrative}`).join(' '),
            remediation:
              'Break the chain at its cheapest link. Each step above cites the statement that permits it; ' +
              'removing any one of them severs the path.',
            principals: [principal.id],
            evidence: best.steps.flatMap((s) => s.evidence),
            confidence: 'certain',
          })
          continue
        }

        // Escalation that stops short of admin but still reaches other identities.
        const gained = reach.capabilities.filter(
          (c) => !(c.kind === 'identity' && c.id === principal.id)
        )
        if (gained.length === 0) continue

        const roleTargets = gained.filter((c) => c.kind === 'identity')
        if (roleTargets.length === 0) continue

        findings.push({
          id: `privilege-escalation-path:${principal.id}`,
          rule: this.id,
          severity: 'high',
          title: `${principal.name} can take on ${roleTargets.length} additional identity(s)`,
          description:
            `${principal.name} can escalate beyond their assigned permissions and act as: ` +
            roleTargets.map((c) => short((c as { id: string }).id)).join(', ') +
            `. Their effective blast radius is the union of everything those identities can do, not what their own policies suggest.`,
          remediation:
            'Review whether each of those identities should genuinely be reachable from this principal. ' +
            'The escalation view shows the specific statement enabling each hop.',
          principals: [principal.id],
          evidence: [...reach.producedBy.values()].flatMap((s) => s.evidence),
          confidence: 'certain',
        })
      }
      return findings
    },
  },
]

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
}

/** Run every rule and return findings, most severe first. */
export function analyseAccount(engine: IamEngine): Finding[] {
  const findings = RULES.flatMap((rule) => {
    try {
      return rule.run(engine)
    } catch (err) {
      // A broken rule must never take down the whole report.
      console.error(`rule ${rule.id} failed:`, err)
      return []
    }
  })

  return findings.sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity])
}

export function severityCounts(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  }
  for (const f of findings) counts[f.severity]++
  return counts
}
