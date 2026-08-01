/**
 * Loading accounts from disk. Server-only — imports node:fs.
 */

import { readFileSync, readdirSync } from 'node:fs'
import path from 'node:path'
import { buildEngine, IamEngine } from './engine'
import { loadAwsAccount, RawAccountManifest } from './normalize/aws'
import { loadIbmAccount, RawIbmManifest } from './normalize/ibm'
import { Account } from './types'

const SAMPLES_DIR = path.join(process.cwd(), 'data', 'samples')

export function listSamples(): { slug: string; name: string }[] {
  return readdirSync(SAMPLES_DIR)
    .filter((f) => f.endsWith('.json'))
    .map((f) => {
      const slug = f.replace(/\.json$/, '')
      const raw = JSON.parse(readFileSync(path.join(SAMPLES_DIR, f), 'utf8'))
      return { slug, name: raw.name ?? slug }
    })
}

/**
 * Dispatch on the manifest's declared provider. Everything downstream sees the
 * same normalised `Account`, so adding a provider never touches the engine,
 * the rules, or the UI.
 */
function normalize(raw: unknown, filename: string, rawText: string): Account {
  const provider = (raw as { provider?: string }).provider ?? 'aws'
  switch (provider) {
    case 'ibm':
      return loadIbmAccount(raw as RawIbmManifest, filename, rawText)
    case 'aws':
      return loadAwsAccount(raw as RawAccountManifest, filename, rawText)
    default:
      throw new Error(`unsupported provider: ${provider}`)
  }
}

export function loadSample(slug: string): { engine: IamEngine; account: Account } {
  // Guard against path traversal — slug comes from the client.
  if (!/^[a-z0-9-]+$/i.test(slug)) throw new Error(`invalid sample: ${slug}`)
  const file = path.join(SAMPLES_DIR, `${slug}.json`)
  const rawText = readFileSync(file, 'utf8')
  const account = normalize(JSON.parse(rawText), `${slug}.json`, rawText)
  return { engine: buildEngine(account), account }
}

/** Parse a manifest the user pasted or uploaded, rather than a bundled sample. */
export function loadFromText(text: string, filename = 'uploaded.json') {
  const account = normalize(JSON.parse(text), filename, text)
  return { engine: buildEngine(account), account }
}
