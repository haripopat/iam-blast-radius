import { Explorer } from '@/components/Explorer'
import { analyseSample } from './actions'
import { listSamples } from '@/lib/iam/load'

export default async function Page() {
  const samples = listSamples()
  const initial = await analyseSample(samples[0].slug)

  return <Explorer samples={samples} initialSlug={samples[0].slug} initial={initial} />
}
