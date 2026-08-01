/**
 * Golden baselines for both sample accounts.
 *
 * These exist because this project has already shipped two real regressions
 * that only manual inspection of CLI output caught:
 *
 *   1. Path reconstruction followed only the acting identity, so a chain that
 *      required joining a group first reported the final hop and silently
 *      dropped the group-join. Bob's three-step route showed as one step.
 *   2. Escalation techniques were not gated by provider. An AWS policy with
 *      `NotAction: ["iam:*"]` matches any action string without a colon —
 *      including IBM's `iam.policy.create` — so an AWS account started
 *      reporting an IBM escalation that could not happen.
 *
 * Both were silent: nothing threw, the UI rendered, the numbers were simply
 * wrong. For a tool whose entire claim is "our answers are checkable", that is
 * the failure mode that matters, so the assertions below pin the exact shape
 * of both accounts rather than just checking nothing crashed.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { loadSample, loadFromText } from '../lib/iam/load.ts'
import { analyseAccount, severityCounts } from '../lib/iam/rules/index.ts'
import { reachableCapabilities, escalationRoutes } from '../lib/iam/escalation.ts'

const PROD_DB = 'arn:aws:rds:eu-west-1:123456789012:cluster:acme-prod-primary'

// ---------------------------------------------------------------------------
// AWS
// ---------------------------------------------------------------------------

test('aws: finding counts by severity', () => {
  const { engine } = loadSample('acme-corp')
  const counts = severityCounts(analyseAccount(engine))
  assert.equal(counts.critical, 4)
  assert.equal(counts.high, 7)
  assert.equal(counts.medium, 1)
})

test('aws: only breakglass-admin reaches full admin', () => {
  const { engine } = loadSample('acme-corp')
  const admins = engine
    .principals()
    .filter((p) => reachableCapabilities(engine, p.id).reachesAdmin)
    .map((p) => p.name)
  assert.deepEqual(admins, ['breakglass-admin'])
})

test('aws: carol does NOT reach admin (regression #2)', () => {
  // Carol's policy is `Allow NotAction: ["iam:*", "kms:Decrypt"]`. That matches
  // any action string without a colon, so before techniques were gated by
  // provider it satisfied IBM's `iam.policy.create` and reported her — and
  // through her, bob — as reaching administrator. Neither can.
  const { engine } = loadSample('acme-corp')
  const carol = engine.principals().find((p) => p.name === 'carol')!
  assert.equal(reachableCapabilities(engine, carol.id).reachesAdmin, false)
})

test('aws: bob reaches the production database by two routes (regression #1)', () => {
  const { engine } = loadSample('acme-corp')
  const bob = engine.principals().find((p) => p.name === 'bob')!
  const routes = escalationRoutes(engine, bob.id, 'rds:DeleteDBCluster', PROD_DB)

  // Shortest first: join the security group and inherit its NotAction grant,
  // or join developers and pass the app role to an EC2 instance.
  assert.equal(routes.length, 2)
  assert.deepEqual(
    routes.map((r) => r.steps.length),
    [1, 2]
  )

  // The three-step route must report the group-join hop, not just the pass-role
  // hop that immediately precedes the action.
  const viaRole = routes[1]
  assert.deepEqual(
    viaRole.steps.map((s) => s.technique),
    ['add-user-to-group', 'pass-role-to-compute']
  )
})

test('aws: every escalation step cites evidence', () => {
  const { engine } = loadSample('acme-corp')
  for (const principal of engine.principals()) {
    const reach = reachableCapabilities(engine, principal.id)
    for (const step of reach.producedBy.values()) {
      assert.ok(
        step.evidence.length > 0,
        `${step.technique} produced a step with no evidence — an unciteable claim`
      )
    }
  }
})

// ---------------------------------------------------------------------------
// IBM Cloud
// ---------------------------------------------------------------------------

test('ibm: finding counts by severity', () => {
  const { engine } = loadSample('ibm-northwind')
  const counts = severityCounts(analyseAccount(engine))
  assert.equal(counts.critical, 4)
  assert.equal(counts.high, 1)
  assert.equal(counts.medium, 0)
})

test('ibm: exactly priya and tom reach admin', () => {
  const { engine } = loadSample('ibm-northwind')
  const admins = engine
    .principals()
    .filter((p) => reachableCapabilities(engine, p.id).reachesAdmin)
    .map((p) => p.name)
    .sort()
  assert.deepEqual(admins, ['priya', 'tom'])
})

test('ibm: dana and the service ID reach nothing', () => {
  const { engine } = loadSample('ibm-northwind')
  for (const name of ['dana', 'etl-pipeline']) {
    const p = engine.principals().find((e) => e.name === name)!
    const reach = reachableCapabilities(engine, p.id)
    assert.equal(reach.reachesAdmin, false, `${name} should not reach admin`)
    assert.equal(reach.capabilities.length, 1, `${name} should gain nothing`)
  }
})

test('ibm: tom escalates via group join then assign-access', () => {
  const { engine } = loadSample('ibm-northwind')
  const tom = engine.principals().find((p) => p.name === 'tom')!
  const reach = reachableCapabilities(engine, tom.id)
  const techniques = [...reach.producedBy.values()].map((s) => s.technique)
  assert.ok(techniques.includes('ibm-join-access-group'))
  assert.ok(techniques.includes('ibm-assign-access'))
})

// ---------------------------------------------------------------------------
// Pasted input
// ---------------------------------------------------------------------------

test('paste: a bare wildcard policy is flagged critical with a rewrite', () => {
  const { engine } = loadFromText(
    JSON.stringify({
      Version: '2012-10-17',
      Statement: [{ Sid: 'God', Effect: 'Allow', Action: '*', Resource: '*' }],
    })
  )
  const findings = analyseAccount(engine)
  const wildcard = findings.find((f) => f.rule === 'wildcard-action-resource')
  assert.ok(wildcard, 'expected a wildcard finding')
  assert.equal(wildcard.severity, 'critical')
  assert.ok(wildcard.rewrite, 'expected a rewrite suggestion')
  assert.ok(!wildcard.rewrite.after.includes('"Resource": "*"'))
})

test('paste: a bucket policy with a wildcard principal is flagged', () => {
  const { engine } = loadFromText(
    JSON.stringify({
      Statement: [
        {
          Effect: 'Allow',
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::x/*',
          Principal: { AWS: '*' },
        },
      ],
    })
  )
  const rules = analyseAccount(engine).map((f) => f.rule)
  assert.ok(rules.includes('public-resource-policy'))
})

test('paste: unusable input fails with a message that explains the shape', () => {
  assert.throws(() => loadFromText('{nope'), /valid JSON/)
  assert.throws(() => loadFromText('{"hello":"world"}'), /Statement/)
})
