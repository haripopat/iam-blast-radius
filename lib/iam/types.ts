/**
 * The normalised IAM model.
 *
 * Every supported cloud provider (AWS, Azure, GCP, IBM Cloud) gets flattened
 * into these types by a normaliser in `lib/iam/normalize/`. Everything
 * downstream — evaluation, risk rules, escalation search — only ever sees
 * this shape, so adding a provider never touches the analysis engine.
 */

export type Provider = 'aws' | 'azure' | 'gcp' | 'ibm'

export type Effect = 'Allow' | 'Deny'

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
}

/**
 * Points at the exact bytes a finding came from. Every finding we emit carries
 * one of these, so the UI can highlight the literal lines that caused it and a
 * reviewer can check our work. Nothing is ever reported without evidence.
 */
export interface SourceRef {
  /** File the statement was loaded from, e.g. `policies/developer-baseline.json` */
  file: string
  /** RFC-6901 JSON pointer into that file, e.g. `/Statement/2` */
  pointer: string
  /** The literal JSON of the statement, pretty-printed, for display */
  snippet: string
  /** 1-indexed line in `file` where the statement starts, when known */
  line?: number
}

export type PrincipalType =
  | 'user'
  | 'role'
  | 'group'
  | 'service'
  | 'account'
  | 'federated'
  | 'wildcard'

export interface Principal {
  type: PrincipalType
  /** Fully-qualified id (ARN for AWS), or `*` for the wildcard principal */
  id: string
}

export interface Condition {
  /** e.g. `StringEquals`, `Bool`, `ArnLike` */
  operator: string
  /** e.g. `aws:MultiFactorAuthPresent`, `sts:ExternalId` */
  key: string
  values: string[]
}

/**
 * One permission grant. Actions and resources may contain `*` / `?` globs and
 * are matched lazily at evaluation time — we never expand the full action
 * universe, because `*` on `*` would be millions of pairs.
 */
export interface Statement {
  /** Stable id used for citation, e.g. `DeveloperBaseline#2` */
  id: string
  sourceRef: SourceRef
  effect: Effect
  actions: string[]
  /** Inverted match: everything EXCEPT these. Widely misread by humans. */
  notActions?: string[]
  resources: string[]
  notResources?: string[]
  /** Only present on resource and trust policies */
  principals?: Principal[]
  notPrincipals?: Principal[]
  conditions: Condition[]
}

export type PolicyKind =
  /** Attached to a user/group/role — grants that identity permissions */
  | 'identity'
  /** Attached to a resource — says who may touch this resource */
  | 'resource'
  /** Attached to a role — says who may become this role */
  | 'trust'

export interface Policy {
  id: string
  name: string
  provider: Provider
  kind: PolicyKind
  statements: Statement[]
  /** For resource policies: the resource this is attached to */
  attachedTo?: string
}

export type EntityType =
  | 'user'
  | 'group'
  | 'role'
  | 'service'
  | 'account'
  | 'resource'

export interface Entity {
  /** ARN or provider-equivalent unique id */
  id: string
  type: EntityType
  name: string
  /** Policy ids attached directly to this entity */
  attachedPolicies: string[]
  /** Group ids this entity belongs to (users only) */
  memberOf?: string[]
  /** Policy id of the trust policy (roles only) */
  trustPolicy?: string
  /** Free-form labels, used to identify production resources etc. */
  tags?: Record<string, string>
}

/** A whole account/subscription/project as loaded from disk. */
export interface Account {
  provider: Provider
  /** Account id, subscription id, or project id */
  id: string
  name: string
  entities: Entity[]
  policies: Policy[]
  /** Accounts we consider ours — trust to anything outside this set is external */
  trustedAccounts?: string[]
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

export type Decision = 'allow' | 'explicit-deny' | 'implicit-deny'

export interface EvaluationResult {
  decision: Decision
  /** Statements that produced the decision — the citation trail */
  matched: Statement[]
  /**
   * Conditions guarding the matched allow statements. An allow that only
   * applies under `aws:MultiFactorAuthPresent` is materially different from an
   * unconditional one, and we surface that rather than silently ignoring it.
   */
  guardedBy: Condition[]
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

/**
 * A concrete narrowed version of the offending statement.
 *
 * Derived deterministically from the account — what the principals are
 * observed to actually use, which roles exist, which groups are unprivileged.
 * No model is involved, so the suggestion is reproducible and can be diffed
 * against the original rather than taken on trust.
 */
export interface Rewrite {
  before: string
  after: string
  /** What the change does and what still needs a human decision. */
  note: string
}

export interface Finding {
  id: string
  /** Rule that produced this, e.g. `wildcard-action-resource` */
  rule: string
  severity: Severity
  title: string
  /** Plain-language explanation. Written by the rule, never by a model. */
  description: string
  /** What to do about it */
  remediation: string
  /** A concrete narrowed statement, where one can be derived */
  rewrite?: Rewrite
  /** Entities affected */
  principals: string[]
  /** Every statement backing this claim */
  evidence: SourceRef[]
  /** Confidence in the finding. Rules that pattern-match structurally are
   *  `certain`; rules that infer intent (e.g. "this looks like prod") are
   *  `probable` and say so in the UI. */
  confidence: 'certain' | 'probable'
}
