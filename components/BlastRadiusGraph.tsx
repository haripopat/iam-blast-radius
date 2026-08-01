'use client'

/**
 * Blast radius.
 *
 * Columns are identity kinds — users, groups, roles — ending at the resource in
 * question. Cold edges are the account as designed: group membership, and
 * grants somebody wrote down. Hot edges are escalation hops the engine proved.
 *
 * The hot edges are the whole point, so they are the only thing that moves:
 * dashes travel along them in the direction of the attack, and the target
 * throws a ring while anything can still reach it. Nobody drew the red lines.
 */

import { useState } from 'react'
import type { Answer } from '@/lib/iam/query'

interface Entity {
  id: string
  name: string
  type: string
  memberOf?: string[]
}

const COL_X = { user: 96, group: 300, role: 512, resource: 734 }
const COL_LABEL = { user: 'Users', group: 'Groups', role: 'Roles', resource: 'Target' }
const NODE_W = 132
const NODE_H = 34
const ROW_GAP = 56
const TOP = 58
const VIEW_W = 830

type Placed = Entity & { x: number; y: number }
type Edge = { from: Placed; to: Placed; label: string; kind: 'member' | 'granted' | 'escalation' }

function layout(entities: Entity[], targetId: string, targetName: string) {
  const byType: Record<string, Entity[]> = { user: [], group: [], role: [] }
  for (const e of entities) {
    if (e.type in byType && e.id !== targetId) byType[e.type].push(e)
  }

  const placed = new Map<string, Placed>()
  const tallest = Math.max(...Object.values(byType).map((l) => l.length), 1)

  for (const [type, list] of Object.entries(byType)) {
    // Centre short columns against the tallest, so the graph reads as one
    // object rather than three ragged stacks.
    const offset = ((tallest - list.length) * ROW_GAP) / 2
    list.forEach((e, i) => {
      placed.set(e.id, {
        ...e,
        x: COL_X[type as keyof typeof COL_X],
        y: TOP + offset + i * ROW_GAP,
      })
    })
  }

  const targetY = TOP + ((tallest - 1) * ROW_GAP) / 2
  placed.set(targetId, {
    id: targetId,
    name: targetName,
    type: 'resource',
    x: COL_X.resource,
    y: targetY,
  })

  return { placed, height: TOP + tallest * ROW_GAP + 34 }
}

function edgePath(from: Placed, to: Placed) {
  const forward = to.x >= from.x
  const x1 = from.x + (forward ? NODE_W / 2 : -NODE_W / 2)
  const y1 = from.y + NODE_H / 2
  const x2 = to.x - (forward ? NODE_W / 2 : -NODE_W / 2)
  const y2 = to.y + NODE_H / 2
  const mid = (x1 + x2) / 2
  return `M ${x1} ${y1} C ${mid} ${y1}, ${mid} ${y2}, ${x2} ${y2}`
}

/** Small type glyph, so a node's kind survives being read at a glance. */
function Glyph({ type, colour }: { type: string; colour: string }) {
  const p = { stroke: colour, strokeWidth: 1.2, fill: 'none' as const }
  if (type === 'group')
    return (
      <>
        <circle cx="4" cy="4.2" r="2" {...p} />
        <circle cx="9.2" cy="4.2" r="2" {...p} />
        <path d="M1 11c0-2 1.4-3.2 3-3.2S7 9 7 11" {...p} />
        <path d="M7.5 11c0-2 1.2-3.2 2.8-3.2S13 9 13 11" {...p} />
      </>
    )
  if (type === 'role') return <path d="M6.5 1.2 11.4 4v5.4L6.5 12.2 1.6 9.4V4z" {...p} />
  if (type === 'resource')
    return (
      <>
        <ellipse cx="6.5" cy="3.4" rx="4.6" ry="1.9" {...p} />
        <path d="M1.9 3.4v6.4c0 1 2 1.9 4.6 1.9s4.6-.9 4.6-1.9V3.4" {...p} />
      </>
    )
  return (
    <>
      <circle cx="6.5" cy="4.2" r="2.4" {...p} />
      <path d="M2 11.4c0-2.3 2-3.6 4.5-3.6S11 9.1 11 11.4" {...p} />
    </>
  )
}

export function BlastRadiusGraph({ entities, answer }: { entities: Entity[]; answer: Answer }) {
  const [hovered, setHovered] = useState<string | null>(null)

  const targetId = answer.parsed.resource
  const targetEntity = entities.find((e) => e.id === targetId)
  const targetName = targetEntity?.name ?? 'target'
  const { placed, height } = layout(entities, targetId, targetName)

  const edges: Edge[] = []
  const push = (fromId: string, toId: string, label: string, kind: Edge['kind']) => {
    const from = placed.get(fromId)
    const to = placed.get(toId)
    if (from && to && from !== to) edges.push({ from, to, label, kind })
  }

  for (const e of entities) {
    for (const g of e.memberOf ?? []) push(e.id, g, 'member of', 'member')
  }
  for (const d of answer.direct) push(d.principal, targetId, 'granted directly', 'granted')

  for (const ind of answer.indirect) {
    for (const route of ind.routes) {
      for (const step of route.steps) {
        push(
          step.actor,
          step.gained.kind === 'admin' ? targetId : step.gained.id,
          step.techniqueName,
          'escalation'
        )
      }
      push(route.via, targetId, 'perform the action', 'escalation')
    }
  }

  const escalatingIds = new Set(answer.indirect.map((i) => i.principal))
  const directIds = new Set(answer.direct.map((d) => d.principal))
  const escalationCount = edges.filter((e) => e.kind === 'escalation').length

  // Hovering isolates a principal and everything it touches. A dense account is
  // unreadable otherwise, and this is the view a reviewer leans into.
  const related = new Set<string>()
  if (hovered) {
    related.add(hovered)
    for (const e of edges) {
      if (e.from.id === hovered) related.add(e.to.id)
      if (e.to.id === hovered) related.add(e.from.id)
    }
  }
  const faded = (...ids: string[]) => (hovered && !ids.every((id) => related.has(id)) ? 'dim' : '')

  return (
    <div className="panel overflow-hidden rounded-xl">
      <div className="graph overflow-x-auto p-2">
        <svg
          viewBox={`0 0 ${VIEW_W} ${height}`}
          className="w-full"
          style={{ minWidth: 720 }}
          role="img"
          aria-label={`Reachability graph for ${targetName}`}
        >
          <defs>
            <marker
              id="tip-cold"
              viewBox="0 0 8 8"
              refX="7"
              refY="4"
              markerWidth="5.5"
              markerHeight="5.5"
              orient="auto"
            >
              <path d="M0,0 L8,4 L0,8 z" fill="#2e3d52" />
            </marker>
            <marker
              id="tip-hot"
              viewBox="0 0 8 8"
              refX="7"
              refY="4"
              markerWidth="6"
              markerHeight="6"
              orient="auto"
            >
              <path d="M0,0 L8,4 L0,8 z" fill="#ff4a5c" />
            </marker>
            <filter id="hot-glow" x="-60%" y="-60%" width="220%" height="220%">
              <feGaussianBlur stdDeviation="3.2" result="b" />
              <feMerge>
                <feMergeNode in="b" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
            <linearGradient id="node-fill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#161f2c" />
              <stop offset="100%" stopColor="#0d131c" />
            </linearGradient>
            <linearGradient id="node-fill-hot" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#2a151b" />
              <stop offset="100%" stopColor="#150c11" />
            </linearGradient>
            <pattern id="graph-grid" width="26" height="26" patternUnits="userSpaceOnUse">
              <path d="M26 0H0V26" fill="none" stroke="rgba(255,255,255,.022)" strokeWidth="1" />
            </pattern>
          </defs>

          <rect width={VIEW_W} height={height} fill="url(#graph-grid)" />

          {(['user', 'group', 'role', 'resource'] as const).map((type) => (
            <g key={type}>
              <text
                x={COL_X[type]}
                y={26}
                textAnchor="middle"
                className="font-mono"
                fontSize="9.5"
                letterSpacing="1.6"
                fill="#4d5a6d"
              >
                {COL_LABEL[type].toUpperCase()}
              </text>
              <line
                x1={COL_X[type] - 46}
                y1={34}
                x2={COL_X[type] + 46}
                y2={34}
                stroke="#1a222f"
                strokeWidth="1"
              />
            </g>
          ))}

          {edges.map((e, i) => {
            const hot = e.kind === 'escalation'
            return (
              <path
                key={`${e.kind}${i}`}
                className={`edge ${faded(e.from.id, e.to.id)}`}
                d={edgePath(e.from, e.to)}
                fill="none"
                stroke={hot ? '#ff4a5c' : '#2e3d52'}
                strokeWidth={hot ? 1.9 : 1.3}
                strokeDasharray={hot ? '7 5' : e.kind === 'granted' ? '4 4' : undefined}
                markerEnd={hot ? 'url(#tip-hot)' : 'url(#tip-cold)'}
                opacity={hot ? 0.92 : 0.72}
                filter={hot ? 'url(#hot-glow)' : undefined}
                style={
                  hot ? { animation: `flow ${1.4 + (i % 3) * 0.25}s linear infinite` } : undefined
                }
              >
                <title>{e.label}</title>
              </path>
            )
          })}

          {[...placed.values()].map((node) => {
            const isTarget = node.id === targetId
            const isEscalator = escalatingIds.has(node.id)
            const isDirect = directIds.has(node.id)
            const accent = isTarget || isEscalator ? '#ff4a5c' : isDirect ? '#4fd8c4' : '#3a4759'
            const text = isTarget
              ? '#ffb3ba'
              : isEscalator
                ? '#ff9a4d'
                : isDirect
                  ? '#4fd8c4'
                  : '#8593a8'

            return (
              <g
                key={node.id}
                className={`node ${faded(node.id)}`}
                onMouseEnter={() => setHovered(node.id)}
                onMouseLeave={() => setHovered(null)}
                style={{ cursor: 'pointer' }}
              >
                {isTarget && answer.indirect.length > 0 && (
                  <rect
                    x={node.x - NODE_W / 2 - 5}
                    y={node.y - 5}
                    width={NODE_W + 10}
                    height={NODE_H + 10}
                    rx="11"
                    fill="none"
                    stroke="#ff4a5c"
                    strokeWidth="1"
                    style={{
                      transformBox: 'fill-box',
                      transformOrigin: 'center',
                      animation: 'ring 2.6s ease-out infinite',
                    }}
                  />
                )}
                <rect
                  x={node.x - NODE_W / 2}
                  y={node.y}
                  width={NODE_W}
                  height={NODE_H}
                  rx="8"
                  fill={isTarget || isEscalator ? 'url(#node-fill-hot)' : 'url(#node-fill)'}
                  stroke={accent}
                  strokeWidth={isTarget || isEscalator || isDirect ? 1.4 : 1}
                />
                <g transform={`translate(${node.x - NODE_W / 2 + 11} ${node.y + NODE_H / 2 - 6.5})`}>
                  <Glyph type={node.type} colour={text} />
                </g>
                <text
                  x={node.x - NODE_W / 2 + 31}
                  y={node.y + NODE_H / 2 + 4}
                  fontSize="11.5"
                  className="font-mono"
                  fill={text}
                >
                  {node.name.length > 15 ? `${node.name.slice(0, 14)}…` : node.name}
                </text>
                <title>{node.id}</title>
              </g>
            )
          })}
        </svg>
      </div>

      <div className="flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-line px-4 py-3 font-mono text-[10px] text-ink-dim">
        <span className="flex items-center gap-2">
          <svg width="22" height="3" aria-hidden>
            <line x1="0" y1="1.5" x2="22" y2="1.5" stroke="#2e3d52" strokeWidth="1.5" />
          </svg>
          group membership
        </span>
        <span className="flex items-center gap-2">
          <svg width="22" height="3" aria-hidden>
            <line
              x1="0"
              y1="1.5"
              x2="22"
              y2="1.5"
              stroke="#2e3d52"
              strokeWidth="1.5"
              strokeDasharray="4 4"
            />
          </svg>
          granted access
        </span>
        <span className="flex items-center gap-2 text-hot">
          <svg width="22" height="3" aria-hidden>
            <line
              x1="0"
              y1="1.5"
              x2="22"
              y2="1.5"
              stroke="#ff4a5c"
              strokeWidth="2"
              strokeDasharray="7 5"
            />
          </svg>
          {escalationCount} escalation {escalationCount === 1 ? 'hop' : 'hops'} — nobody designed
          these
        </span>
        <span className="ml-auto hidden text-ink-faint sm:block">hover a node to isolate it</span>
      </div>
    </div>
  )
}
