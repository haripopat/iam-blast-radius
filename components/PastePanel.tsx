'use client'

const PLACEHOLDER = `{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": "*", "Resource": "*" }
  ]
}`

export function PastePanel({
  text,
  onChange,
  onAnalyse,
  onCancel,
  error,
  busy,
}: {
  text: string
  onChange: (v: string) => void
  onAnalyse: () => void
  onCancel: () => void
  error: string | null
  busy: boolean
}) {
  return (
    <section className="panel rise overflow-hidden rounded-xl">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-line px-4 py-2.5">
        <span className="flex gap-1.5" aria-hidden>
          <span className="h-2.5 w-2.5 rounded-full bg-[#ff5f57]" />
          <span className="h-2.5 w-2.5 rounded-full bg-[#febc2e]" />
          <span className="h-2.5 w-2.5 rounded-full bg-[#28c840]" />
        </span>
        <span className="ml-1 font-mono text-[12px] text-ink">your-policy.json</span>
        <span className="ml-auto font-mono text-[10px] text-ink-faint">
          a policy document, an array of them, or a whole account manifest
        </span>
      </div>

      <textarea
        value={text}
        onChange={(e) => onChange(e.target.value)}
        spellCheck={false}
        rows={12}
        placeholder={PLACEHOLDER}
        aria-label="Policy JSON"
        className="block w-full resize-y bg-[#080b11] px-4 py-3 font-mono text-[12px] leading-[1.7] text-[#b6c2d4] outline-none placeholder:text-ink-faint/45"
      />

      {error && (
        <p
          className="border-t px-4 py-2.5 font-mono text-[12px]"
          style={{
            color: 'var(--color-hot)',
            borderColor: 'rgba(255,74,92,.25)',
            background: 'rgba(255,74,92,.07)',
          }}
        >
          {error}
        </p>
      )}

      <div className="flex flex-wrap items-center gap-2 border-t border-line px-4 py-3">
        <button
          onClick={onAnalyse}
          disabled={busy || !text.trim()}
          className="btn-primary px-4 py-2 text-[13px]"
        >
          {busy ? 'Analysing' : 'Analyse'}
        </button>
        <button onClick={onCancel} className="btn-ghost px-4 py-2 text-[13px]">
          Cancel
        </button>
        <span className="ml-auto font-mono text-[10px] text-ink-faint">
          parsed in this session — nothing is stored
        </span>
      </div>
    </section>
  )
}
