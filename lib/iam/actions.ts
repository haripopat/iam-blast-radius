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
 */
export function allKnownActions(): string[] {
  const out = new Set<string>(['*'])
  for (const svc of SERVICE_CATALOGUE) {
    for (const action of Object.values(svc.actions)) out.add(action)
  }
  return [...out]
}

/** Which service does a question token point at? */
export function serviceForToken(token: string): ServiceActions | undefined {
  const lower = token.toLowerCase()
  return SERVICE_CATALOGUE.find((s) => s.aliases.includes(lower))
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
