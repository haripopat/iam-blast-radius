/**
 * Glob matching for actions, resources and principals.
 *
 * IAM uses `*` (any sequence) and `?` (any single character). This is NOT a
 * regex dialect, so we escape everything else. Getting this wrong is how tools
 * end up hallucinating permissions, which is the single thing the brief calls
 * out, so it lives in one small, heavily-used function.
 */

const globCache = new Map<string, RegExp>()

export function globToRegExp(pattern: string): RegExp {
  const cached = globCache.get(pattern)
  if (cached) return cached

  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&')
  const source = '^' + escaped.replace(/\*/g, '.*').replace(/\?/g, '.') + '$'
  // IAM action and ARN matching is case-insensitive in practice.
  const re = new RegExp(source, 'i')
  globCache.set(pattern, re)
  return re
}

export function globMatches(pattern: string, value: string): boolean {
  if (pattern === '*') return true
  if (pattern === value) return true
  if (!pattern.includes('*') && !pattern.includes('?')) {
    return pattern.toLowerCase() === value.toLowerCase()
  }
  return globToRegExp(pattern).test(value)
}

export function anyGlobMatches(patterns: string[], value: string): boolean {
  return patterns.some((p) => globMatches(p, value))
}

/** True if the pattern is `*` or matches an implausibly wide slice, e.g. `s3:*`. */
export function isWildcard(pattern: string): boolean {
  return pattern === '*'
}

/** `iam:PassRole` -> `iam`; `*` -> `*`. */
export function actionService(action: string): string {
  const idx = action.indexOf(':')
  return idx === -1 ? action : action.slice(0, idx)
}

/**
 * Rough "is this destructive" classifier used for blast-radius wording.
 * Deliberately conservative — it only affects how we phrase a finding, never
 * whether a permission is considered granted.
 */
const DESTRUCTIVE_VERBS =
  /^(delete|terminate|remove|destroy|revoke|disable|purge|drop|put|write|update|modify|create|attach|detach|set|reset)/i

export function isDestructiveAction(action: string): boolean {
  const verb = action.includes(':') ? action.slice(action.indexOf(':') + 1) : action
  return DESTRUCTIVE_VERBS.test(verb)
}

// ---------------------------------------------------------------------------
// ARN parsing
// ---------------------------------------------------------------------------

export interface ParsedArn {
  partition: string
  service: string
  region: string
  account: string
  resourceType: string
  resourceId: string
}

/** arn:aws:iam::123456789012:role/ec2-app-role */
export function parseArn(arn: string): ParsedArn | null {
  if (!arn.startsWith('arn:')) return null
  const parts = arn.split(':')
  if (parts.length < 6) return null
  const tail = parts.slice(5).join(':')
  const slash = tail.indexOf('/')
  const [resourceType, resourceId] =
    slash === -1 ? [tail, tail] : [tail.slice(0, slash), tail.slice(slash + 1)]
  return {
    partition: parts[1],
    service: parts[2],
    region: parts[3],
    account: parts[4],
    resourceType,
    resourceId,
  }
}

export function accountOf(arn: string): string | null {
  return parseArn(arn)?.account ?? null
}

/**
 * IBM Cloud CRN:
 * `crn:v1:bluemix:public:cloud-object-storage:global:a/ACCT:INSTANCE::`
 *
 * Segments are positional and may be empty, so we index rather than split on
 * a delimiter that also appears inside values.
 */
export interface ParsedCrn {
  version: string
  cname: string
  ctype: string
  service: string
  region: string
  scope: string
  instance: string
  resourceType: string
  resource: string
}

export function parseCrn(crn: string): ParsedCrn | null {
  if (!crn.startsWith('crn:')) return null
  const p = crn.split(':')
  if (p.length < 10) return null
  return {
    version: p[1],
    cname: p[2],
    ctype: p[3],
    service: p[4],
    region: p[5],
    scope: p[6],
    instance: p[7],
    resourceType: p[8],
    resource: p[9],
  }
}

/**
 * The service segment of a resource id, whichever provider it came from.
 * Everything downstream keys off this rather than caring about ARN vs CRN.
 */
export function resourceService(id: string): string | null {
  return parseArn(id)?.service ?? parseCrn(id)?.service ?? null
}

/** Account / subscription / project id for a resource id, either format. */
export function resourceAccount(id: string): string | null {
  const arn = parseArn(id)
  if (arn) return arn.account
  const crn = parseCrn(id)
  if (!crn) return null
  // CRN scope is `a/<account-id>` for account-scoped resources.
  return crn.scope.startsWith('a/') ? crn.scope.slice(2) : crn.scope || null
}

/** `arn:aws:iam::123456789012:root` means "any principal in that account". */
export function isAccountRootArn(arn: string): boolean {
  const parsed = parseArn(arn)
  return parsed?.service === 'iam' && parsed.resourceType === 'root'
}
