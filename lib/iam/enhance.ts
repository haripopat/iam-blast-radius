/**
 * The AI layer — and the tight leash it runs on.
 *
 * The deterministic parser in `query.ts` handles clean phrasings. This layer
 * handles the messy ones ("can the summer intern nuke our customer data?")
 * by asking Claude to translate the question into a concrete query.
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

import Anthropic from '@anthropic-ai/sdk'
import { IamEngine } from './engine'
import { ParsedQuestion } from './query'
import { parseArn } from './match'
import { allKnownActions } from './actions'

const MODEL = 'claude-opus-5'

/**
 * The closed set the model picks from — read from the shared catalogue so it
 * can never drift from what the deterministic parser and the engine know.
 */
const KNOWN_ACTIONS = allKnownActions()

/**
 * Ask Claude to turn a question into an (action, resource) pair.
 * Returns null whenever anything at all goes wrong.
 *
 * No credential check up front: the SDK resolves an API key, an auth token, or
 * an `ant auth login` profile on its own, and throws immediately if it finds
 * none. Letting that throw land in the catch below covers every credential
 * source without us having to enumerate them.
 */
export async function parseQuestionWithModel(
  engine: IamEngine,
  question: string
): Promise<ParsedQuestion | null> {
  const resources = engine.entities('resource')
  if (resources.length === 0) return null

  // The enum IS the guardrail: the model selects an identifier, it does not
  // author one. '*' means "anywhere in the account".
  const resourceIds = [...resources.map((r) => r.id), '*']

  const inventory = resources
    .map((r) => {
      const service = parseArn(r.id)?.service ?? 'unknown'
      const tags = r.tags ? ` tags=${JSON.stringify(r.tags)}` : ''
      return `- ${r.id}\n    name=${r.name} service=${service}${tags}`
    })
    .join('\n')

  try {
    const client = new Anthropic()
    const response = await client.messages.create({
      model: MODEL,
      max_tokens: 2048,
      output_config: {
        effort: 'low',
        format: {
          type: 'json_schema',
          schema: {
            type: 'object',
            properties: {
              action: {
                type: 'string',
                enum: KNOWN_ACTIONS,
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
                  'One plain sentence restating the question as the query you chose, shown to the user so they can correct you.',
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
        },
      },
      system:
        'You translate plain-English questions about cloud permissions into a single ' +
        'concrete IAM query. You are a translation layer only: you never decide who ' +
        'can do what, and you never assess risk. A separate deterministic engine ' +
        'answers the query you produce.\n\n' +
        'Pick the action and resource that best match the question. Both must come ' +
        'from the allowed values. Prefer the most destructive plausible action when ' +
        'the user asks about damage or risk, because the answer should cover the ' +
        'worst case. Set confident to false whenever more than one resource could ' +
        'reasonably be meant.',
      messages: [
        {
          role: 'user',
          content:
            `Resources in this account:\n${inventory}\n\n` +
            `Question: ${question}`,
        },
      ],
    })

    const text = response.content.find((b) => b.type === 'text')?.text
    if (!text) return null

    const raw = JSON.parse(text) as {
      action: string
      resource: string
      interpretation: string
      confident: boolean
    }

    // Belt and braces: verify the model stayed inside the closed set, even
    // though the schema should already have guaranteed it.
    if (!KNOWN_ACTIONS.includes(raw.action)) return null
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
    // Any failure at all falls back to the deterministic parser.
    return null
  }
}
