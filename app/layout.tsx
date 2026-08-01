import type { Metadata } from 'next'
import { Bricolage_Grotesque, IBM_Plex_Mono, IBM_Plex_Sans } from 'next/font/google'
import './globals.css'

/**
 * IBM Plex carries the interface because this is built for the IBM challenge
 * and the tool reads IBM Cloud accounts. Plex Mono does most of the work —
 * ARNs, actions, policy JSON and counts are all evidence, and evidence reads
 * as mono. Bricolage is the display voice: headings, numerals, the wordmark.
 */
const bricolage = Bricolage_Grotesque({
  variable: '--font-bricolage',
  subsets: ['latin'],
  weight: ['600', '700', '800'],
})

const plexSans = IBM_Plex_Sans({
  variable: '--font-plex-sans',
  subsets: ['latin'],
  weight: ['400', '500', '600'],
})

const plexMono = IBM_Plex_Mono({
  variable: '--font-plex-mono',
  subsets: ['latin'],
  weight: ['400', '500', '600'],
})

export const metadata: Metadata = {
  title: 'IAM Blast Radius',
  description:
    'Every other tool tells you who holds a permission. This tells you who can take it.',
}

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html
      lang="en"
      className={`${bricolage.variable} ${plexSans.variable} ${plexMono.variable} h-full antialiased`}
    >
      <body className="min-h-full">{children}</body>
    </html>
  )
}
