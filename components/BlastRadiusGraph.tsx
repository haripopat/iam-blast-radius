'use client'

/**
 * Blast radius view.
 *
 * Columns are identity kinds (users, groups, roles) ending at the resource in
 * question. Grey edges are the org chart as designed — group membership and
 * granted access. Red edges are the escalation hops the engine proved, which
 * is the whole point: the red lines are the ones nobody drew on purpose.
 */

import type { Answer } from '@/lib/iam/query'

interface Entity {
  id: string
  name: string
  type: string
  memberOf?: string[]
}

const COL_X = { user: 90, group: 290, role: 500, resource: 720 }
const NODE_W = 130
const NODE_H = 30
const ROW_GAP = 52
const TOP = 46

type Placed = Entity & { x: number; y: number }

function layout(entities: Entity[], targetId: string, targetName: string) {
  const byType: Record<string, Entity[]> = { user: [], group: [], role: [] }
  for (const e of entities) {
    if (e.type in byType) byType[e.type].push(e)
  }

  const placed = new Map<string, Placed>()
  for (const [type, list] of Object.entries(byType)) {
    list.forEach((e, i) => {
      placed.set(e.id, {
        ...e,
        x: COL_X[type as keyof typeof COL_X],
        y: TOP + i * ROW_GAP,
      })
    })
  }

  const tallest = Math.max(...Object.values(byType).map((l) => l.length), 1)
  placed.set(targetId, {
    id: targetId,
    name: targetName,
    type: 'resource',
    x: COL_X.resource,
    y: TOP + ((tallest - 1) * ROW_GAP) / 2,
  })

  return { placed, height: TOP + tallest * ROW_GAP + 30 }
}

function edgePath(from: Placed, to: Placed) {
  const x1 = from.x + NODE_W / 2
  const y1 = from.y + NODE_H / 2
  const x2 = to.x - NODE_W / 2
  const y2 = to.y + NODE_H / 2
  const mid = (x1 + x2) / 2
  return `M ${x1} ${y1} C ${mid} ${y1}, ${mid} ${y2}, ${x2} ${y2}`
}

export function BlastRadiusGraph({
  entities,
  answer,
}: {
  entities: Entity[]
  answer: Answer
}) {
  const targetId = answer.parsed.resource
  const targetEntity = entities.find((e) => e.id === targetId)
  const targetName = targetEntity?.name ?? 'target'

  const { placed, height } = layout(entities, targetId, targetName)

  // Grey: group membership, as designed.
  const membershipEdges: { from: Placed; to: Placed }[] = []
  for (const e of entities) {
    for (const g of e.memberOf ?? []) {
      const from = placed.get(e.id)
      const to = placed.get(g)
      if (from && to) membershipEdges.push({ from, to })
    }
  }

  // Grey: principals who already hold the permission.
  const directEdges: { from: Placed; to: Placed }[] = []
  for (const d of answer.direct) {
    const from = placed.get(d.principal)
    const to = placed.get(targetId)
    if (from && to) directEdges.push({ from, to })
  }

  // Red: every proved escalation hop, plus the final reach to the resource.
  const escalationEdges: { from: Placed; to: Placed; label: string }[] = []
  for (const ind of answer.indirect) {
    for (const route of ind.routes) {
      for (const step of route.steps) {
        const from = placed.get(step.actor)
        const to =
          step.gained.kind === 'admin' ? placed.get(targetId) : placed.get(step.gained.id)
        if (from && to && from !== to) {
          escalationEdges.push({ from, to, label: step.techniqueName })
        }
      }
      const last = placed.get(route.via)
      const target = placed.get(targetId)
      if (last && target && last !== target) {
        escalationEdges.push({ from: last, to: target, label: 'perform action' })
      }
    }
  }

  const escalatingIds = new Set(answer.indirect.map((i) => i.principal))

  return (
    <div className="overflow-x-auto rounded-lg border border-[#1e2635] bg-[#0b0e14] p-4">
      <svg viewBox={`0 0 800 ${height}`} className="w-full" style={{ minWidth: 700 }}>
        <defs>
          <marker id="arrow-grey" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="6" markerHeight="6" orient="auto">
            <path d="M0,0 L8,4 L0,8 z" fill="#30363d" />
          </marker>
          <marker id="arrow-red" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="6" markerHeight="6" orient="auto">
            <path d="M0,0 L8,4 L0,8 z" fill="#f85149" />
          </marker>
        </defs>

        {(['user', 'group', 'role', 'resource'] as const).map((type) => (
          <text
            key={type}
            x={COL_X[type]}
            y={22}
            textAnchor="middle"
            className="fill-[#5a6472] font-mono"
            fontSize="10"
            letterSpacing="1"
          >
            {type.toUpperCase()}S
          </text>
        ))}

        {membershipEdges.map((e, i) => (
          <path
            key={`m${i}`}
            d={edgePath(e.from, e.to)}
            fill="none"
            stroke="#30363d"
            strokeWidth="1.5"
            markerEnd="url(#arrow-grey)"
          />
        ))}

        {directEdges.map((e, i) => (
          <path
            key={`d${i}`}
            d={edgePath(e.from, e.to)}
            fill="none"
            stroke="#30363d"
            strokeWidth="1.5"
            strokeDasharray="4 3"
            markerEnd="url(#arrow-grey)"
          />
        ))}

        {escalationEdges.map((e, i) => (
          <path
            key={`e${i}`}
            d={edgePath(e.from, e.to)}
            fill="none"
            stroke="#f85149"
            strokeWidth="2"
            markerEnd="url(#arrow-red)"
            opacity="0.85"
          >
            <title>{e.label}</title>
          </path>
        ))}

        {[...placed.values()].map((node) => {
          const isTarget = node.id === targetId
          const isEscalator = escalatingIds.has(node.id)
          const fill = isTarget ? '#f85149' : isEscalator ? '#1a1214' : '#111621'
          const stroke = isTarget ? '#f85149' : isEscalator ? '#f85149' : '#1e2635'
          return (
            <g key={node.id}>
              <rect
                x={node.x - NODE_W / 2}
                y={node.y}
                width={NODE_W}
                height={NODE_H}
                rx="6"
                fill={fill}
                fillOpacity={isTarget ? 0.15 : 1}
                stroke={stroke}
                strokeWidth={isTarget || isEscalator ? 1.5 : 1}
              />
              <text
                x={node.x}
                y={node.y + NODE_H / 2 + 4}
                textAnchor="middle"
                fontSize="11"
                className="font-mono"
                fill={isTarget ? '#f85149' : isEscalator ? '#f0883e' : '#8b949e'}
              >
                {node.name.length > 16 ? `${node.name.slice(0, 15)}…` : node.name}
              </text>
            </g>
          )
        })}
      </svg>

      <div className="mt-3 flex flex-wrap items-center gap-4 border-t border-[#1e2635] pt-3 font-mono text-[10px] text-[#8b949e]">
        <span className="flex items-center gap-1.5">
          <svg width="20" height="2">
            <line x1="0" y1="1" x2="20" y2="1" stroke="#30363d" strokeWidth="2" />
          </svg>
          group membership
        </span>
        <span className="flex items-center gap-1.5">
          <svg width="20" height="2">
            <line x1="0" y1="1" x2="20" y2="1" stroke="#30363d" strokeWidth="2" strokeDasharray="4 3" />
          </svg>
          granted access
        </span>
        <span className="flex items-center gap-1.5">
          <svg width="20" height="2">
            <line x1="0" y1="1" x2="20" y2="1" stroke="#f85149" strokeWidth="2" />
          </svg>
          <span className="text-[#f85149]">escalation path — nobody designed these</span>
        </span>
      </div>
    </div>
  )
}
