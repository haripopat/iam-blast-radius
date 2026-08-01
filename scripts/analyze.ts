/**
 * CLI harness for the analysis engine.
 *
 * Lets the engine be developed and checked without waiting on the UI:
 *
 *   npx tsx scripts/analyze.ts data/samples/acme-corp.json \
 *     "rds:DeleteDBCluster" "arn:aws:rds:eu-west-1:123456789012:cluster:acme-prod-primary"
 */

import path from 'node:path'
import { loadSample } from '../lib/iam/load'
import { reachableCapabilities, whoCanReach } from '../lib/iam/escalation'
import { analyseAccount, severityCounts } from '../lib/iam/rules'

const [, , target, action, resource] = process.argv

if (!target) {
  console.error('usage: analyze.ts <sample-slug | path/to/account.json> [action] [resource]')
  process.exit(1)
}

// Accept either a bare slug or a path, so existing invocations keep working.
const slug = path.basename(target).replace(/\.json$/, '')
const { engine, account } = loadSample(slug)

const bold = (s: string) => `\x1b[1m${s}\x1b[0m`
const dim = (s: string) => `\x1b[2m${s}\x1b[0m`
const red = (s: string) => `\x1b[31m${s}\x1b[0m`
const yellow = (s: string) => `\x1b[33m${s}\x1b[0m`
const green = (s: string) => `\x1b[32m${s}\x1b[0m`

/** Prefer the entity's own name — an IBM `IBMid-550000BBBB` has nothing to trim. */
const short = (id: string) => {
  const named = engine.entity(id)?.name
  if (named) return named
  const i = id.lastIndexOf('/')
  return i === -1 ? id : id.slice(i + 1)
}

console.log()
console.log(bold(`${account.name} (${account.id})`))
console.log(
  dim(
    `${account.entities.length} entities, ${account.policies.length} policies, ` +
      `${account.policies.reduce((n, p) => n + p.statements.length, 0)} statements`
  )
)

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

const findings = analyseAccount(engine)
const counts = severityCounts(findings)

console.log()
console.log(
  bold('Findings  ') +
    red(`${counts.critical} critical`) +
    '  ' +
    yellow(`${counts.high} high`) +
    '  ' +
    `${counts.medium} medium`
)
console.log()
for (const f of findings) {
  const tag =
    f.severity === 'critical'
      ? red('CRITICAL')
      : f.severity === 'high'
        ? yellow('HIGH    ')
        : `${f.severity.toUpperCase().padEnd(8)}`
  console.log(`  ${tag} ${bold(f.title)} ${dim(`[${f.confidence}]`)}`)
  console.log(`           ${f.description}`)
  console.log(dim(`           fix: ${f.remediation}`))
  for (const ev of f.evidence.slice(0, 3)) {
    console.log(dim(`           ${ev.file}${ev.pointer}${ev.line ? ` (line ${ev.line})` : ''}`))
  }
  console.log()
}

// ---------------------------------------------------------------------------
// Reachability summary for every principal
// ---------------------------------------------------------------------------

console.log()
console.log(bold('Privilege escalation summary'))
for (const principal of engine.principals()) {
  const reach = reachableCapabilities(engine, principal.id)
  const gained = reach.capabilities.filter((c) => c.kind !== 'identity' || c.id !== principal.id)
  const label = reach.reachesAdmin
    ? red('reaches ADMIN')
    : gained.length > 0
      ? yellow(`gains ${gained.length} capability(s)`)
      : green('no escalation found')
  console.log(`  ${short(principal.id).padEnd(20)} ${label}`)
}

// ---------------------------------------------------------------------------
// The headline query
// ---------------------------------------------------------------------------

if (action && resource) {
  console.log()
  console.log(bold(`Who can perform ${action}`))
  console.log(dim(`  on ${resource}`))
  console.log()

  const { direct, indirect } = whoCanReach(engine, action, resource)

  console.log(bold('  Direct access'))
  if (direct.length === 0) console.log(dim('    none'))
  for (const d of direct) {
    console.log(`    ${green('•')} ${short(d.principal)}`)
    for (const ev of d.evidence) {
      console.log(dim(`        ${ev.file}${ev.pointer}${ev.line ? ` (line ${ev.line})` : ''}`))
    }
  }

  console.log()
  console.log(bold('  Reachable by privilege escalation'))
  if (indirect.length === 0) console.log(dim('    none'))
  for (const { principal, routes } of indirect) {
    console.log(
      `    ${red('•')} ${bold(short(principal))} ` +
        dim(`— ${routes.length} independent route${routes.length === 1 ? '' : 's'}`)
    )
    routes.forEach((route, r) => {
      console.log(
        `      ${dim(`route ${r + 1}:`)} via ${short(route.via)} ` +
          dim(`(${route.steps.length + 1} steps)`)
      )
      route.steps.forEach((step, n) => {
        console.log(`        ${n + 1}. ${yellow(step.techniqueName)}`)
        console.log(`           ${step.narrative}`)
        for (const ev of step.evidence) {
          console.log(
            dim(`           evidence: ${ev.file}${ev.pointer}${ev.line ? ` (line ${ev.line})` : ''}`)
          )
        }
      })
      console.log(`        ${route.steps.length + 1}. ${yellow('Perform the action')}`)
      console.log(`           As ${short(route.via)}, run ${action} on the target.`)
      for (const ev of route.finalEvidence) {
        console.log(
          dim(`           evidence: ${ev.file}${ev.pointer}${ev.line ? ` (line ${ev.line})` : ''}`)
        )
      }
    })
  }
}

console.log()
