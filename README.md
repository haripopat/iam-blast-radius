# IAM Blast Radius

**Every other tool tells you who holds a permission. This tells you who can take it.**

Built for the IBM Challenge at the Cursor Cybersecurity Hackathon.

---

## The problem

Cloud IAM policies are dense JSON, and the dangerous part isn't any single policy — it's the combination. Some permissions let you acquire *other* permissions. A person with a harmless-looking role can pick up a second one, which opens a third, which reaches production.

Permission reports check policies one at a time, so they never see the chain.

## What this does

Ask a question in plain English. Get back two lists: who can do it **directly**, and who can **reach** it by escalating first — with the exact route and the exact lines of JSON that permit each hop.

On the bundled demo account, "who can delete the production database?" returns the two names you'd expect, plus:

- **alice**, a developer, in 2 steps — she can pass the app role to an EC2 instance she launches
- **bob**, a summer intern with a read-only account, in 3 steps — he can add himself to the developers group, then do what alice can
- **carol**, a "SecurityAudit" user, *directly* — her policy uses `NotAction`, which grants everything **except** a short list

No individual policy in that account looks wrong.

## Why you can trust the answers

**The model never decides anything.** The verdicts come from a policy evaluator that implements the documented IAM evaluation rules — explicit deny beats allow, allow beats implicit deny, with three-state condition handling so an unresolvable condition is reported as *conditional* rather than guessed either way.

Claude sits at one edge only: it turns your English question into an `(action, resource)` pair. It picks from a JSON-schema `enum` built from the account itself, so it physically cannot name a resource that doesn't exist — and we re-validate its answer against the engine anyway. If it's unavailable or returns anything unverifiable, a deterministic parser answers instead and the UI says which one ran.

**Every finding carries a receipt** — file, JSON pointer, line number, and the literal statement. Disagree with us and check.

## Run it

```bash
npm install && npm run dev
```

Then open http://localhost:3000. No API key needed — the deterministic parser handles the demo questions. Set `ANTHROPIC_API_KEY` to enable Claude for messier phrasings.

Engine-only, no UI:

```bash
npx tsx scripts/analyze.ts data/samples/acme-corp.json "rds:DeleteDBCluster" "arn:aws:rds:eu-west-1:123456789012:cluster:acme-prod-primary"
```

## How it works

```
lib/iam/
  types.ts          normalised model — every provider flattens into this
  match.ts          IAM glob matching, ARN parsing
  engine.ts         the evaluator: can(principal, action, resource) -> decision + citations
  escalation.ts     fixpoint search over escalation techniques -> multi-hop routes
  rules/            deterministic risk rules -> findings with severity + remediation
  query.ts          deterministic English -> query
  enhance.ts        Claude English -> query, on a closed set, with fallback
  normalize/aws.ts  AWS IAM JSON -> normalised model
```

The core is a **capability fixpoint**. Start with the identity an attacker controls; repeatedly apply every known escalation technique to whatever they control so far; stop when nothing new is reachable. A hop is only added if the evaluator independently proves it, and each step records what it depended on — so walking the graph backwards reconstructs the whole route, not just the last move.

Techniques are encoded as data from the documented AWS escalation methods: join a privileged group, rewrite an attached policy, attach a policy to yourself, pass a role to compute you control, assume a role that trusts you, rewrite a trust policy, mint credentials for another user.

Roles don't inherit a user's group memberships — getting that wrong invents permissions that don't exist, which is the exact failure mode this tool exists to catch.

## Findings

Alongside the Q&A, the rules engine flags: wildcard action-on-resource, wildcard trust principals, publicly readable resources, cross-account trust without `sts:ExternalId`, `NotAction` inversions, `iam:PassRole` on every role, self-service group membership, and admin roles with no MFA condition — each with severity, plain-language explanation, remediation, and evidence.

Findings are marked `certain` when the structure itself is the problem, and `inferred` when we read intent from something softer like a resource tag. The UI shows the difference.
