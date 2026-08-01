/**
 * The AI layer — and the tight leash it runs on.
 *
 * The deterministic parser in `query.ts` handles clean phrasings. This layer
 * handles the messy ones ("what happens if bob goes rogue?") by asking Gemini
 * to translate the question into a concrete query.
 *
 * Three constraints keep it honest:
 *
 *  1. **Closed set.** The resource and action are `enum` fields in a JSON
 *     schema built from the account itself. The model physically cannot name
 *     a resource that does not exist — it is picking from a list, not
 *     generating a string.
 *  2. **Post-validation.** We re-check the model's answer against the engine
 *     anyway. Schema enforcement is a good lock; it is not a reason to skip
 *     checking the door.
 *  3. **Fallback, never failure.** Any error — no API key, network, malformed
 *     output, a resource we don't recognise — returns null and the
 *     deterministic parser answers instead. The product degrades to "slightly
 *     worse at parsing English", never to "wrong answer".
 *
 * The model never sees a policy document and never decides who can do what.
 * It maps English onto an identifier. That is the whole job.
 */

import { GoogleGenAI, ThinkingLevel } from '@google/genai'
import { IamEngine } from './engine'
import { ParsedQuestion } from './query'
import { resourceService } from './match'
import { allKnownActions } from './actions'
import { servicesInAccount } from './query'

/**
 * Models to try, in order.
 *
 * Two things drive this list. First, thinking is turned down to MINIMAL:
 * this is a translation task, not a reasoning task, and the difference is
 * dramatic — at the default thinking level the same call takes ~21s, which is
 * unusable interactively. At MINIMAL it is ~1.1s with identical output on our
 * test questions.
 *
 * Second, free-tier Gemini enforces a per-minute quota, and a burst of
 * questions during a demo will trip it. Rather than let one 429 drop us all
 * the way back to keyword matching, we fall through to a second model with
 * its own quota pool. Only if every model fails do we return null.
 */
const MODELS = ['gemini-3-flash-preview', 'gemini-flash-lite-latest']
const THINKING_LEVEL = ThinkingLevel.MINIMAL

/**
 * The closed set the model picks from — read from the shared catalogue so it
 * can never drift from what the deterministic parser and the engine know.
 */
function knownActionsFor(engine: IamEngine): string[] {
  return allKnownActions(servicesInAccount(engine))
}

function apiKey(): string | undefined {
  return process.env.GEMINI_API_KEY ?? process.env.GOOGLE_API_KEY
}

export function isModelParserAvailable(): boolean {
  return Boolean(apiKey())
}

/**
 * Ask Gemini to turn a question into an (action, resource) pair.
 * Returns null whenever anything at all goes wrong.
 */
export async function parseQuestionWithModel(
  engine: IamEngine,
  question: string
): Promise<ParsedQuestion | null> {
  const key = apiKey()
  if (!key) return null

  const resources = engine.entities('resource')
  if (resources.length === 0) return null

  // The enum IS the guardrail: the model selects an identifier, it does not
  // author one. '*' means "anywhere in the account".
  const resourceIds = [...resources.map((r) => r.id), '*']

  const inventory = resources
    .map((r) => {
      const service = resourceService(r.id) ?? 'unknown'
      const tags = r.tags ? ` tags=${JSON.stringify(r.tags)}` : ''
      return `- ${r.id}\n    name=${r.name} service=${service}${tags}`
    })
    .join('\n')

  const knownActions = knownActionsFor(engine)
  const ai = new GoogleGenAI({ apiKey: key })

  for (const model of MODELS) {
    const parsed = await tryModel(ai, model, engine, resources, resourceIds, inventory, question, knownActions)
    if (parsed) return parsed
  }
  return null
}

async function tryModel(
  ai: GoogleGenAI,
  model: string,
  engine: IamEngine,
  resources: ReturnType<IamEngine['entities']>,
  resourceIds: string[],
  inventory: string,
  question: string,
  knownActions: string[]
): Promise<ParsedQuestion | null> {
  try {
    const response = await ai.models.generateContent({
      model,
      contents: `Resources in this account:\n${inventory}\n\nQuestion: ${question}`,
      config: {
        thinkingConfig: { thinkingLevel: THINKING_LEVEL },
        responseMimeType: 'application/json',
        responseJsonSchema: {
          type: 'object',
          properties: {
            action: {
              type: 'string',
              enum: knownActions,
              description: 'The IAM action the question is asking about.',
            },
            resource: {
              type: 'string',
              enum: resourceIds,
              description:
                'The ARN of the resource being asked about, or "*" for the whole account.',
            },
            interpretation: {
              type: 'string',
              description:
                'Restate the query you chose, starting with "Who can" and naming the ' +
                'action and the resource in plain words. No first person, no ' +
                'explanation. Example: "Who can read the production database credentials".',
            },
            confident: {
              type: 'boolean',
              description:
                'False if the question was ambiguous or you had to guess which resource was meant.',
            },
          },
          required: ['action', 'resource', 'interpretation', 'confident'],
          additionalProperties: false,
        },
        systemInstruction:
          'You translate plain-English questions about cloud permissions into a single ' +
          'concrete IAM query. You are a translation layer only: you never decide who ' +
          'can do what, and you never assess risk. A separate deterministic engine ' +
          'answers the query you produce.\n\n' +
          'Pick the action and resource that best match the question. Both must come ' +
          'from the allowed values. Prefer the most destructive plausible action when ' +
          'the user asks about damage or risk, because the answer should cover the ' +
          'worst case. Set confident to false whenever more than one resource could ' +
          'reasonably be meant.',
      },
    })

    const text = response.text
    if (!text) return null

    const raw = JSON.parse(text) as {
      action: string
      resource: string
      interpretation: string
      confident: boolean
    }

    // Belt and braces: verify the model stayed inside the closed set, even
    // though the schema should already have guaranteed it.
    if (!knownActions.includes(raw.action)) return null
    if (raw.resource !== '*' && !engine.entity(raw.resource)) return null

    return {
      action: raw.action,
      resource: raw.resource,
      interpretation: raw.interpretation,
      confidence: raw.confident ? 'exact' : 'inferred',
      alternatives: resources
        .filter((r) => r.id !== raw.resource)
        .slice(0, 3)
        .map((r) => ({ label: r.name, resource: r.id })),
    }
  } catch {
    // Quota, network, malformed output — try the next model, and if this was
    // the last one the caller falls back to the deterministic parser.
    return null
  }
}
