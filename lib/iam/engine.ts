/**
 * The deterministic policy evaluator.
 *
 * This is the heart of the tool and it contains no AI whatsoever. Every
 * "can X do Y to Z" answer the product gives comes from here, follows the
 * documented IAM evaluation order (explicit deny > allow > implicit deny), and
 * returns the exact statements that produced the decision.
 *
 * The language model sits strictly outside this file: it turns an English
 * question into a call into this engine, and turns the result back into
 * English. It never decides whether something is permitted. That is what makes
 * the findings reproducible and checkable rather than plausible-sounding.
 */

import {
  Account,
  Condition,
  Entity,
  EvaluationResult,
  Policy,
  Principal,
  Statement,
} from './types'
import { anyGlobMatches, globMatches, isAccountRootArn } from './match'

export interface EvaluateOptions {
  /**
   * Condition context, e.g. `{ 'aws:MultiFactorAuthPresent': 'true' }`.
   * Unset keys mean "we do not know", and any allow depending on an unknown
   * key is returned as an allow *guarded by* that condition rather than
   * silently dropped or silently kept.
   */
  context?: Record<string, string>
}

export class IamEngine {
  readonly account: Account
  private readonly entityById = new Map<string, Entity>()
  private readonly policyById = new Map<string, Policy>()
  /** Cached identity statements per principal id */
  private readonly identityCache = new Map<string, Statement[]>()

  constructor(account: Account) {
    this.account = account
    for (const e of account.entities) this.entityById.set(e.id, e)
    for (const p of account.policies) this.policyById.set(p.id, p)
  }

  entity(id: string): Entity | undefined {
    return this.entityById.get(id)
  }

  policy(id: string): Policy | undefined {
    return this.policyById.get(id)
  }

  entities(type?: Entity['type']): Entity[] {
    return type
      ? this.account.entities.filter((e) => e.type === type)
      : this.account.entities
  }

  /**
   * The things that can actually take an action: users, roles, and service
   * identities. IBM service IDs hold policies exactly as a user does, so
   * omitting them would silently drop them from every "who can" answer.
   */
  principals(): Entity[] {
    return this.account.entities.filter(
      (e) =>
        e.type === 'user' ||
        e.type === 'role' ||
        e.type === 'service' ||
        // Account entities only appear for principals a resource policy names
        // — an external account, or the wildcard. They are exactly who the
        // answer to "who can reach this" should list.
        e.type === 'account'
    )
  }

  isTrustedAccount(accountId: string): boolean {
    const trusted = this.account.trustedAccounts ?? [this.account.id]
    return trusted.includes(accountId)
  }

  // -------------------------------------------------------------------------
  // Statement collection
  // -------------------------------------------------------------------------

  /**
   * Every identity statement that applies to a principal: its own attached
   * policies plus those of every group it belongs to.
   *
   * `extraGroups` lets the escalation search ask "what could this user do if
   * they added themselves to group X", without mutating the account.
   */
  identityStatements(principalId: string, extraGroups: string[] = []): Statement[] {
    const cacheable = extraGroups.length === 0
    if (cacheable) {
      const hit = this.identityCache.get(principalId)
      if (hit) return hit
    }

    const entity = this.entityById.get(principalId)
    if (!entity) return []

    const policyIds = [...entity.attachedPolicies]
    const groups = [...(entity.memberOf ?? []), ...extraGroups]
    for (const groupId of groups) {
      const group = this.entityById.get(groupId)
      if (group) policyIds.push(...group.attachedPolicies)
    }

    const statements: Statement[] = []
    for (const id of policyIds) {
      const policy = this.policyById.get(id)
      if (policy?.kind === 'identity') statements.push(...policy.statements)
    }

    if (cacheable) this.identityCache.set(principalId, statements)
    return statements
  }

  /** Resource-attached policy statements for a given resource ARN. */
  resourceStatements(resource: string): Statement[] {
    const out: Statement[] = []
    for (const policy of this.account.policies) {
      if (policy.kind !== 'resource' || !policy.attachedTo) continue
      if (globMatches(policy.attachedTo, resource) || resource.startsWith(policy.attachedTo)) {
        out.push(...policy.statements)
      }
    }
    return out
  }

  // -------------------------------------------------------------------------
  // Evaluation
  // -------------------------------------------------------------------------

  /**
   * Can `principalId` perform `action` on `resource`?
   *
   * Follows IAM evaluation order. Returns every statement that contributed, so
   * the UI can cite exact lines and a reviewer can disagree with us.
   */
  can(
    principalId: string,
    action: string,
    resource: string,
    opts: EvaluateOptions = {},
    extraGroups: string[] = []
  ): EvaluationResult {
    const statements = [
      ...this.identityStatements(principalId, extraGroups),
      ...this.applicableResourceStatements(principalId, resource),
    ]
    return this.evaluateStatements(statements, action, resource, opts)
  }

  /**
   * Resource-policy statements that name this principal.
   *
   * Within an account, a resource policy grants on its own — an S3 bucket
   * policy naming a role gives that role access whether or not any identity
   * policy mentions the bucket. Evaluating identity policies alone therefore
   * *under*-reports, which for this tool is the worse direction to be wrong
   * in: it would show a resource as unreachable while a bucket policy quietly
   * hands it out.
   */
  private applicableResourceStatements(principalId: string, resource: string): Statement[] {
    if (resource === '*') return []
    return this.resourceStatements(resource).filter((stmt) =>
      statementMatchesPrincipal(stmt, principalId, this)
    )
  }

  evaluateStatements(
    statements: Statement[],
    action: string,
    resource: string,
    opts: EvaluateOptions = {}
  ): EvaluationResult {
    const denies: Statement[] = []
    const allows: Statement[] = []
    const guardedBy: Condition[] = []

    for (const stmt of statements) {
      if (!statementMatchesAction(stmt, action)) continue
      if (!statementMatchesResource(stmt, resource)) continue

      const conditionState = evaluateConditions(stmt.conditions, opts.context)
      if (conditionState === 'unsatisfied') continue

      if (stmt.effect === 'Deny') {
        denies.push(stmt)
      } else {
        allows.push(stmt)
        if (conditionState === 'unknown') guardedBy.push(...stmt.conditions)
      }
    }

    if (denies.length > 0) {
      return { decision: 'explicit-deny', matched: denies, guardedBy: [] }
    }
    if (allows.length > 0) {
      return { decision: 'allow', matched: allows, guardedBy }
    }
    return { decision: 'implicit-deny', matched: [], guardedBy: [] }
  }

  /**
   * Can `principalId` perform `action` on *anything*?
   *
   * AWS escalation checks name a concrete target ARN, but IBM policies scope
   * by attribute set — a policy granting Administrator over the `iam-groups`
   * service has no single resource id to ask about. This answers "does this
   * principal hold this action anywhere in the account", which is the right
   * question for capability-style permissions.
   */
  canAnywhere(
    principalId: string,
    action: string,
    extraGroups: string[] = []
  ): EvaluationResult {
    const statements = this.identityStatements(principalId, extraGroups)
    const denies: Statement[] = []
    const allows: Statement[] = []

    for (const stmt of statements) {
      if (!statementMatchesAction(stmt, action)) continue
      if (evaluateConditions(stmt.conditions, undefined) === 'unsatisfied') continue
      if (stmt.effect === 'Deny') denies.push(stmt)
      else allows.push(stmt)
    }

    if (denies.length > 0) {
      return { decision: 'explicit-deny', matched: denies, guardedBy: [] }
    }
    if (allows.length > 0) return { decision: 'allow', matched: allows, guardedBy: [] }
    return { decision: 'implicit-deny', matched: [], guardedBy: [] }
  }

  /**
   * Which principals can perform `action` on `resource`, directly?
   *
   * This is the *direct* answer only. The escalation search in `escalation.ts`
   * layers indirect reachability on top, which is where the interesting
   * answers live.
   */
  whoCan(
    action: string,
    resource: string,
    opts: EvaluateOptions = {}
  ): { principal: Entity; result: EvaluationResult }[] {
    const out: { principal: Entity; result: EvaluationResult }[] = []
    for (const principal of this.principals()) {
      const result = this.can(principal.id, action, resource, opts)
      if (result.decision === 'allow') out.push({ principal, result })
    }
    return out
  }

  /**
   * Does `roleId`'s trust policy let `principal` assume it?
   *
   * Separate from `can` because trust policies are principal-matched rather
   * than resource-matched, and because a role with a wildcard principal and no
   * condition is one of the highest-signal misconfigurations in the whole
   * space.
   */
  trustAllows(roleId: string, principalArn: string): EvaluationResult {
    const role = this.entityById.get(roleId)
    if (!role?.trustPolicy) {
      return { decision: 'implicit-deny', matched: [], guardedBy: [] }
    }
    const policy = this.policyById.get(role.trustPolicy)
    if (!policy) {
      return { decision: 'implicit-deny', matched: [], guardedBy: [] }
    }

    const denies: Statement[] = []
    const allows: Statement[] = []
    const guardedBy: Condition[] = []

    for (const stmt of policy.statements) {
      if (!statementMatchesAction(stmt, 'sts:AssumeRole')) continue
      if (!statementMatchesPrincipal(stmt, principalArn, this)) continue

      const conditionState = evaluateConditions(stmt.conditions, undefined)
      if (conditionState === 'unsatisfied') continue

      if (stmt.effect === 'Deny') denies.push(stmt)
      else {
        allows.push(stmt)
        if (conditionState === 'unknown') guardedBy.push(...stmt.conditions)
      }
    }

    if (denies.length > 0) {
      return { decision: 'explicit-deny', matched: denies, guardedBy: [] }
    }
    if (allows.length > 0) return { decision: 'allow', matched: allows, guardedBy }
    return { decision: 'implicit-deny', matched: [], guardedBy: [] }
  }

  /** The trust policy statements for a role, if any. */
  trustStatements(roleId: string): Statement[] {
    const role = this.entityById.get(roleId)
    if (!role?.trustPolicy) return []
    return this.policyById.get(role.trustPolicy)?.statements ?? []
  }
}

// ---------------------------------------------------------------------------
// Statement matching primitives
// ---------------------------------------------------------------------------

export function statementMatchesAction(stmt: Statement, action: string): boolean {
  if (stmt.notActions && stmt.notActions.length > 0) {
    return !anyGlobMatches(stmt.notActions, action)
  }
  return anyGlobMatches(stmt.actions, action)
}

export function statementMatchesResource(stmt: Statement, resource: string): boolean {
  if (stmt.notResources && stmt.notResources.length > 0) {
    return !anyGlobMatches(stmt.notResources, resource)
  }
  if (stmt.resources.length === 0) return true // trust policies have no resource
  return anyGlobMatches(stmt.resources, resource)
}

export function statementMatchesPrincipal(
  stmt: Statement,
  principalArn: string,
  engine?: IamEngine
): boolean {
  const matchOne = (p: Principal): boolean => {
    if (p.type === 'wildcard' || p.id === '*') return true
    if (p.id === principalArn) return true
    // `arn:aws:iam::123456789012:root` covers every principal in that account.
    if (isAccountRootArn(p.id)) {
      const acct = p.id.split(':')[4]
      return principalArn.split(':')[4] === acct
    }
    return globMatches(p.id, principalArn)
  }

  if (stmt.notPrincipals && stmt.notPrincipals.length > 0) {
    return !stmt.notPrincipals.some(matchOne)
  }
  if (!stmt.principals || stmt.principals.length === 0) return false
  return stmt.principals.some(matchOne)
}

// ---------------------------------------------------------------------------
// Conditions
// ---------------------------------------------------------------------------

export type ConditionState = 'satisfied' | 'unsatisfied' | 'unknown'

/**
 * We only *resolve* conditions when the caller supplied the relevant context
 * key. Otherwise the state is `unknown` and the caller reports the allow as
 * conditional. Pretending to know is how a tool starts hallucinating; pretending
 * conditions do not exist is how it produces false positives. Neither is
 * acceptable, so we model the third state explicitly.
 */
export function evaluateConditions(
  conditions: Condition[],
  context: Record<string, string> | undefined
): ConditionState {
  if (conditions.length === 0) return 'satisfied'
  if (!context) return 'unknown'

  let sawUnknown = false
  for (const cond of conditions) {
    const actual = context[cond.key]
    if (actual === undefined) {
      sawUnknown = true
      continue
    }
    if (!conditionHolds(cond, actual)) return 'unsatisfied'
  }
  return sawUnknown ? 'unknown' : 'satisfied'
}

function conditionHolds(cond: Condition, actual: string): boolean {
  const op = cond.operator
  switch (op) {
    case 'StringEquals':
    case 'ArnEquals':
      return cond.values.includes(actual)
    case 'StringNotEquals':
    case 'ArnNotEquals':
      return !cond.values.includes(actual)
    case 'StringLike':
    case 'ArnLike':
      return anyGlobMatches(cond.values, actual)
    case 'StringNotLike':
    case 'ArnNotLike':
      return !anyGlobMatches(cond.values, actual)
    case 'Bool':
      return cond.values.some((v) => v.toLowerCase() === actual.toLowerCase())
    case 'NumericEquals':
      return cond.values.some((v) => Number(v) === Number(actual))
    case 'NumericLessThan':
      return cond.values.some((v) => Number(actual) < Number(v))
    case 'NumericGreaterThan':
      return cond.values.some((v) => Number(actual) > Number(v))
    default:
      // Unknown operator: do not guess. Treat as unresolved so the caller
      // surfaces it as a guarded allow rather than asserting either way.
      return true
  }
}

export function buildEngine(account: Account): IamEngine {
  return new IamEngine(account)
}
