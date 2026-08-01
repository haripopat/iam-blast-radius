/**
 * Least-privilege rewrites.
 *
 * A finding that only says "this is too broad" leaves the reader with the hard
 * part still to do. These helpers turn each finding into a concrete narrowed
 * statement they can diff against the original and paste back.
 *
 * Everything here is derived from the account itself — the actions a principal
 * is *observed* to use elsewhere, the roles that actually exist, the groups
 * that carry no privileged policy. No model is involved, so a suggestion is
 * reproducible and checkable rather than plausible.
 *
 * Where a decision genuinely belongs to a human (which external ID to use,
 * which actions a wildcard was standing in for) the rewrite says so in its
 * `note` instead of inventing a value.
 */

import { IamEngine } from '../engine'
import { Rewrite, Statement } from '../types'

/**
 * Rewrite by mutating a parsed copy of the statement's own JSON.
 *
 * Working from `sourceRef.snippet` rather than rebuilding from the normalised
 * model means `before` and `after` are directly comparable and nothing —
 * `Sid`, ordering, unrelated keys — is silently dropped in translation.
 */
export function rewriteStatement(
  statement: Statement,
  mutate: (draft: Record<string, unknown>) => void,
  note: string
): Rewrite | undefined {
  try {
    const before = statement.sourceRef.snippet
    const draft = JSON.parse(before) as Record<string, unknown>
    mutate(draft)
    return { before, after: JSON.stringify(draft, null, 2), note }
  } catch {
    // A snippet we cannot round-trip is not one we should be rewriting.
    return undefined
  }
}

/**
 * Every action these principals are granted by statements *other* than the one
 * being rewritten. This is the evidence for what a wildcard was standing in
 * for: if the rest of their access only ever mentions S3 and EC2, proposing
 * those is a defensible narrowing rather than a guess.
 */
export function observedActions(
  engine: IamEngine,
  principals: string[],
  excludeStatementId: string
): string[] {
  const actions = new Set<string>()
  for (const principal of principals) {
    for (const stmt of engine.identityStatements(principal)) {
      if (stmt.id === excludeStatementId) continue
      if (stmt.effect !== 'Allow') continue
      for (const action of stmt.actions) {
        if (action === '*') continue
        actions.add(action)
      }
    }
  }
  return [...actions].sort()
}

/** Role ARNs in the account — the candidate set for a scoped `iam:PassRole`. */
export function roleArns(engine: IamEngine): string[] {
  return engine.entities('role').map((r) => r.id)
}

/**
 * Groups that carry no privileged policy, so self-service membership of them
 * is defensible. A group is privileged if anything attached to it grants a
 * wildcard action or touches IAM.
 */
export function unprivilegedGroups(engine: IamEngine): string[] {
  return engine
    .entities('group')
    .filter((group) => {
      for (const policyId of group.attachedPolicies) {
        const policy = engine.policy(policyId)
        if (!policy) continue
        for (const stmt of policy.statements) {
          if (stmt.effect !== 'Allow') continue
          if (stmt.notActions?.length) return false
          if (
            stmt.actions.some(
              (a) => a === '*' || a.toLowerCase().startsWith('iam:') || a.endsWith(':*')
            )
          ) {
            return false
          }
        }
      }
      return true
    })
    .map((g) => g.id)
}

/** Collapse a long action list so a suggestion stays readable. */
export function summarise(actions: string[], limit = 12): string[] {
  if (actions.length <= limit) return actions
  return [...actions.slice(0, limit), `… and ${actions.length - limit} more`]
}
