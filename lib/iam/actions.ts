/**
 * The action catalogue.
 *
 * Single source of truth for "which IAM actions are we willing to claim we
 * understand". Both the deterministic parser (`query.ts`) and the model's
 * schema enum (`enhance.ts`) read from here, so the two can never drift —
 * previously they were two hand-maintained lists, which is exactly the kind of
 * duplication that produces a model allowed to name an action the engine has
 * never heard of.
 *
 * It is deliberately a curated table rather than the full AWS action universe
 * (~18,000 actions across ~400 services). A wrong action name yields a
 * confidently wrong answer, so we only list actions we are sure of, and say so
 * when a question falls outside the table.
 */

export type VerbClass = 'delete' | 'read' | 'write' | 'admin'

export interface ServiceActions {
  /** ARN service segment, e.g. `rds` */
  service: string
  /** Human label used in interpretations, e.g. "database" */
  label: string
  /** Words in a question that point at this service */
  aliases: string[]
  actions: Record<VerbClass, string>
}

export const SERVICE_CATALOGUE: ServiceActions[] = [
  {
    service: 'rds',
    label: 'database',
    aliases: ['database', 'databases', 'db', 'rds', 'postgres', 'mysql', 'aurora'],
    actions: {
      delete: 'rds:DeleteDBCluster',
      read: 'rds:DescribeDBClusters',
      write: 'rds:ModifyDBCluster',
      admin: 'rds:*',
    },
  },
  {
    service: 's3',
    label: 'bucket',
    aliases: ['bucket', 'buckets', 's3', 'backup', 'backups', 'object', 'objects', 'storage', 'files'],
    actions: {
      delete: 's3:DeleteObject',
      read: 's3:GetObject',
      write: 's3:PutObject',
      admin: 's3:*',
    },
  },
  {
    service: 'ec2',
    label: 'compute instance',
    aliases: ['instance', 'instances', 'ec2', 'server', 'servers', 'vm', 'compute', 'machine'],
    actions: {
      delete: 'ec2:TerminateInstances',
      read: 'ec2:DescribeInstances',
      write: 'ec2:RunInstances',
      admin: 'ec2:*',
    },
  },
  {
    service: 'iam',
    label: 'identity and access management',
    aliases: ['iam', 'permission', 'permissions', 'policy', 'policies', 'admin', 'administrator', 'privileges'],
    actions: {
      delete: 'iam:DeleteUser',
      read: 'iam:GetUser',
      write: 'iam:CreateUser',
      admin: 'iam:*',
    },
  },
  {
    service: 'kms',
    label: 'encryption key',
    aliases: ['kms', 'key', 'keys', 'encryption', 'encrypted', 'decrypt', 'ciphertext'],
    actions: {
      delete: 'kms:ScheduleKeyDeletion',
      read: 'kms:Decrypt',
      write: 'kms:Encrypt',
      admin: 'kms:*',
    },
  },
  {
    service: 'secretsmanager',
    label: 'secret',
    aliases: ['secret', 'secrets', 'credential', 'credentials', 'password', 'passwords', 'apikey', 'token', 'tokens'],
    actions: {
      delete: 'secretsmanager:DeleteSecret',
      read: 'secretsmanager:GetSecretValue',
      write: 'secretsmanager:PutSecretValue',
      admin: 'secretsmanager:*',
    },
  },
  {
    service: 'lambda',
    label: 'function',
    aliases: ['lambda', 'function', 'functions', 'serverless'],
    actions: {
      delete: 'lambda:DeleteFunction',
      read: 'lambda:GetFunction',
      write: 'lambda:UpdateFunctionCode',
      admin: 'lambda:*',
    },
  },
  {
    service: 'dynamodb',
    label: 'table',
    aliases: ['dynamodb', 'dynamo', 'table', 'tables', 'nosql'],
    actions: {
      delete: 'dynamodb:DeleteTable',
      read: 'dynamodb:GetItem',
      write: 'dynamodb:PutItem',
      admin: 'dynamodb:*',
    },
  },
  {
    service: 'ssm',
    label: 'parameter',
    aliases: ['ssm', 'parameter', 'parameters', 'paramstore'],
    actions: {
      delete: 'ssm:DeleteParameter',
      read: 'ssm:GetParameter',
      write: 'ssm:PutParameter',
      admin: 'ssm:*',
    },
  },
  {
    service: 'logs',
    label: 'log group',
    aliases: ['log', 'logs', 'cloudwatch', 'logging'],
    actions: {
      delete: 'logs:DeleteLogGroup',
      read: 'logs:GetLogEvents',
      write: 'logs:PutLogEvents',
      admin: 'logs:*',
    },
  },
  {
    service: 'cloudtrail',
    label: 'audit trail',
    aliases: ['cloudtrail', 'audit', 'trail', 'tracks'],
    actions: {
      delete: 'cloudtrail:DeleteTrail',
      read: 'cloudtrail:LookupEvents',
      write: 'cloudtrail:PutEventSelectors',
      admin: 'cloudtrail:*',
    },
  },
  {
    service: 'sqs',
    label: 'queue',
    aliases: ['sqs', 'queue', 'queues'],
    actions: {
      delete: 'sqs:DeleteQueue',
      read: 'sqs:ReceiveMessage',
      write: 'sqs:SendMessage',
      admin: 'sqs:*',
    },
  },
  {
    service: 'sns',
    label: 'topic',
    aliases: ['sns', 'topic', 'topics', 'notification', 'notifications'],
    actions: {
      delete: 'sns:DeleteTopic',
      read: 'sns:GetTopicAttributes',
      write: 'sns:Publish',
      admin: 'sns:*',
    },
  },
  {
    service: 'ecr',
    label: 'container image',
    aliases: ['ecr', 'image', 'images', 'container', 'containers', 'registry', 'docker'],
    actions: {
      delete: 'ecr:BatchDeleteImage',
      read: 'ecr:BatchGetImage',
      write: 'ecr:PutImage',
      admin: 'ecr:*',
    },
  },
  {
    service: 'eks',
    label: 'Kubernetes cluster',
    aliases: ['eks', 'kubernetes', 'k8s'],
    actions: {
      delete: 'eks:DeleteCluster',
      read: 'eks:DescribeCluster',
      write: 'eks:UpdateClusterConfig',
      admin: 'eks:*',
    },
  },
  {
    service: 'sts',
    label: 'role assumption',
    aliases: ['sts', 'assume', 'impersonate', 'switch role'],
    actions: {
      delete: 'sts:AssumeRole',
      read: 'sts:GetCallerIdentity',
      write: 'sts:AssumeRole',
      admin: 'sts:*',
    },
  },

  // -------------------------------------------------------------------------
  // IBM Cloud. Actions follow IBM's own `<service>.<resourceType>.<operation>`
  // convention rather than being coerced into AWS syntax. Service names are
  // IBM's, so these coexist with the AWS entries in one catalogue without
  // colliding.
  // -------------------------------------------------------------------------
  {
    service: 'databases-for-postgresql',
    label: 'database',
    aliases: ['postgres', 'postgresql', 'database', 'databases', 'db'],
    actions: {
      delete: 'databases-for-postgresql.*.delete',
      read: 'databases-for-postgresql.*.get',
      write: 'databases-for-postgresql.*.update',
      admin: 'databases-for-postgresql.*.*',
    },
  },
  {
    service: 'cloud-object-storage',
    label: 'object storage bucket',
    aliases: ['cos', 'bucket', 'buckets', 'archive', 'backup', 'backups', 'object storage'],
    actions: {
      delete: 'cloud-object-storage.*.delete',
      read: 'cloud-object-storage.data.read',
      write: 'cloud-object-storage.data.write',
      admin: 'cloud-object-storage.*.*',
    },
  },
  {
    service: 'secrets-manager',
    label: 'secret',
    aliases: ['secret', 'secrets', 'credential', 'credentials'],
    actions: {
      delete: 'secrets-manager.*.delete',
      read: 'secrets-manager.data.read',
      write: 'secrets-manager.data.write',
      admin: 'secrets-manager.*.*',
    },
  },
  {
    service: 'iam-groups',
    label: 'access group',
    aliases: ['access group', 'access groups', 'iam-groups'],
    actions: {
      delete: 'iam-groups.groups.delete',
      read: 'iam-groups.groups.get',
      write: 'iam-groups.groups.update',
      admin: 'iam-groups.*.*',
    },
  },
  {
    service: 'iam-identity',
    label: 'service ID',
    aliases: ['service id', 'service ids', 'iam-identity', 'api key', 'api keys'],
    actions: {
      delete: 'iam-identity.serviceid.delete',
      read: 'iam-identity.serviceid.get',
      write: 'iam-identity.serviceid.create',
      admin: 'iam-identity.*.*',
    },
  },
]

const BY_SERVICE = new Map(SERVICE_CATALOGUE.map((s) => [s.service, s]))

export function serviceActions(service: string): ServiceActions | undefined {
  return BY_SERVICE.get(service)
}

/** The concrete action for a (service, verb) pair, or a service wildcard. */
export function actionFor(service: string, verb: VerbClass): string {
  return BY_SERVICE.get(service)?.actions[verb] ?? `${service}:*`
}

/**
 * Every action we recognise. This becomes the model's schema `enum`, so it is
 * the hard ceiling on what the model can ask the engine about.
 *
 * Pass the services actually present in the account to scope it. Offering an
 * AWS action against an IBM account (or vice versa) can only ever produce a
 * query nothing matches, so narrowing the enum removes a whole class of
 * confidently-empty answers.
 */
export function allKnownActions(presentServices?: Iterable<string>): string[] {
  const allowed = presentServices ? new Set(presentServices) : null
  const out = new Set<string>(['*'])
  for (const svc of SERVICE_CATALOGUE) {
    if (allowed && !allowed.has(svc.service)) continue
    for (const action of Object.values(svc.actions)) out.add(action)
  }
  // A question about an account with no recognised services still needs
  // something to pick, so fall back to the whole catalogue.
  return out.size > 1 ? [...out] : allKnownActions()
}

/**
 * Which service does a question token point at?
 *
 * Aliases deliberately overlap across providers — "database" means `rds` on
 * AWS and `databases-for-postgresql` on IBM. `present` breaks the tie in
 * favour of a service the account actually has, so the same question works on
 * either account without the user knowing which cloud they're looking at.
 */
export function serviceForToken(
  token: string,
  present?: Set<string>
): ServiceActions | undefined {
  const lower = token.toLowerCase()
  const matches = SERVICE_CATALOGUE.filter((s) => s.aliases.includes(lower))
  if (matches.length === 0) return undefined
  if (present) {
    const inAccount = matches.find((s) => present.has(s.service))
    if (inAccount) return inAccount
  }
  return matches[0]
}

// ---------------------------------------------------------------------------
// Verbs
// ---------------------------------------------------------------------------

/** Order matters: the first match wins, so destructive verbs are listed first. */
const VERB_PATTERNS: { pattern: RegExp; verb: VerbClass }[] = [
  {
    pattern: /\b(delete|drop|destroy|remove|terminate|wipe|purge|nuke|kill|erase)\b/i,
    verb: 'delete',
  },
  {
    pattern: /\b(write|modify|change|update|edit|upload|put|rotate|tamper|encrypt)\b/i,
    verb: 'write',
  },
  {
    pattern:
      /\b(read|access|download|view|see|get|list|exfiltrate|steal|leak|leaked|expose|exposed|reach|decrypt)\b/i,
    verb: 'read',
  },
  {
    pattern:
      /\b(admin|administrator|full control|anything|everything|take over|escalate|compromise|rogue|breach)\b/i,
    verb: 'admin',
  },
]

/**
 * Classify the question's intent. Destructive verbs win over read verbs when
 * both appear, because a security answer should cover the worst case.
 */
export function detectVerb(question: string): VerbClass {
  for (const { pattern, verb } of VERB_PATTERNS) {
    if (pattern.test(question)) return verb
  }
  return 'admin'
}
