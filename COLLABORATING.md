# Working on this in parallel

Two branches, split so they barely touch the same files. The goal is that
neither of us spends the last hour of the hackathon resolving conflicts.

| Branch | Owns | Roughly |
|---|---|---|
| `feat/engine` | `lib/iam/**`, `scripts/`, `tests/`, `data/samples/` | evaluation, escalation, findings rules, normalisers |
| `feat/ui` | `components/**`, `app/page.tsx` | everything the judge actually looks at |

Branch off `main`, not off each other. Merge back into `main` when a piece works.

## The two shared files

Only two files sit on the seam:

- **`lib/iam/types.ts`** — the `Finding` / `Rewrite` / `Statement` shapes
- **`app/actions.ts`** — the `AnalysisPayload` and `Source` shapes the UI receives

**If you need to change either, say so before you do.** Adding an optional field
is safe and needs no ceremony. Renaming or removing one breaks the other branch
silently, because TypeScript will only complain on the branch that hasn't
changed yet.

Everything else is owned by exactly one branch.

## Setup

```bash
git clone https://github.com/haripopat/iam-blast-radius.git
cd iam-blast-radius
npm install
npm run dev
```

Open http://localhost:3000. It works with no API key — the deterministic parser
handles the demo questions, and the badge in the answer panel says "parsed by
rules" so you can see which path ran.

To enable the Gemini translation layer, put a key in `.env.local`:

```
GEMINI_API_KEY=your-key-here
```

`.env.local` is gitignored. **Do not commit a key**, and don't paste one into a
PR description or an issue — get your own from
[aistudio.google.com](https://aistudio.google.com/apikey) rather than sharing
one, since the free tier is rate-limited per key and two people hammering the
same key will trip it during the demo.

## Before you push

```bash
npm test        # 12 golden tests over both sample accounts
npm run build   # typecheck + production build
```

The tests pin exact numbers: finding counts by severity, who reaches admin, the
technique sequence of bob's three-step route. **If they fail, that is the point
— they exist because this project has already shipped two silent regressions
where nothing threw and the numbers were quietly wrong.** Don't update the
expected values to make them pass unless you have worked out why the behaviour
changed and are confident the new number is the correct one.

## Quick map

```
lib/iam/
  engine.ts        can(principal, action, resource) -> decision + citations
  escalation.ts    fixpoint search -> multi-hop routes. Techniques are gated by
                   provider, and that gating is load-bearing (see the comment)
  rules/index.ts   findings; rules/rewrite.ts derives the suggested fixes
  query.ts         deterministic English -> query
  enhance.ts       Gemini English -> query, closed enum, falls back to query.ts
  normalize/       aws.ts, ibm.ts -> the shared model in types.ts
components/
  Explorer.tsx     the whole UI: question box, findings, paste panel
  BlastRadiusGraph.tsx
```

The engine contains no AI at all. The model only ever turns a question into an
`(action, resource)` pair chosen from a fixed list, and gets re-validated before
use. Keep it that way — it is the reason the findings are checkable, and it is
the main thing that distinguishes this from a chat wrapper.
