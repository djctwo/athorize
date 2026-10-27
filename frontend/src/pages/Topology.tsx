import { useState, useMemo, useCallback, useRef, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../lib/api'
import type { ITAsset, OTAsset } from '../types'
import { EmptyState } from '../components/EmptyState'
import { Search, ZoomIn, ZoomOut, Network, Download, Printer } from 'lucide-react'

type LayerModel = 'purdue' | 'enterprise'

interface TopoNode {
  id: string
  name: string
  type: 'it' | 'ot'
  ip: string
  layer: string
  vendor: string
  role: string
  connectedTo: string[]
  patchStatus: string
}

const PURDUE_LAYERS = ['DMZ', 'LEVEL_3', 'LEVEL_2', 'LEVEL_1', 'LEVEL_0']
const ENTERPRISE_LAYERS = ['PERIMETER', 'CLOUD', 'INTERNAL', 'ENDPOINTS']

const PURDUE_LABELS: Record<string, string> = {
  DMZ: 'DMZ — Industrial Demilitarized Zone',
  LEVEL_3: 'Level 3 — Site Operations',
  LEVEL_2: 'Level 2 — Area Supervisory',
  LEVEL_1: 'Level 1 — Basic Control',
  LEVEL_0: 'Level 0 — Physical Process',
}

const ENTERPRISE_LABELS: Record<string, string> = {
  PERIMETER: 'Perimeter — Firewalls & Edge',
  CLOUD: 'Cloud — Hosted Resources',
  INTERNAL: 'Internal — Servers & Services',
  ENDPOINTS: 'Endpoints — Workstations & Devices',
}

function itToLayer(a: ITAsset): string {
  const role = (a.asset_role || '').toUpperCase()
  if (role === 'NETWORK_DEVICE') return 'PERIMETER'
  if (role === 'CLOUD_RESOURCE') return 'CLOUD'
  if (role === 'SERVER' || role === 'VM' || role === 'CONTAINER' || role === 'APPLIANCE') return 'INTERNAL'
  return 'ENDPOINTS'
}

function itToNode(a: ITAsset): TopoNode {
  return {
    id: `it-${a.id}`,
    name: a.asset_name,
    type: 'it',
    ip: a.ip_address || '',
    layer: itToLayer(a),
    vendor: a.vendor || '',
    role: a.asset_role || '',
    connectedTo: (a.connected_to || []).map(c => c.trim()),
    patchStatus: a.patch_status || '',
  }
}

function otToNode(a: OTAsset): TopoNode {
  return {
    id: `ot-${a.id}`,
    name: a.asset_name,
    type: 'ot',
    ip: a.ip_address || '',
    layer: (a.purdue_level || 'LEVEL_2').toUpperCase().replace(/\s+/g, '_'),
    vendor: a.vendor || '',
    role: a.asset_type || '',
    connectedTo: (a.connected_to || []).map(c => c.trim()),
    patchStatus: a.patch_status || '',
  }
}

const NODE_W = 140
const NODE_H = 48
const NODE_GAP_X = 16
const NODE_GAP_Y = 12
const LAYER_PAD_Y = 40
const LAYER_LABEL_H = 28
const MAX_COLS = 8

function buildLayout(nodes: TopoNode[], layers: string[]) {
  const byLayer: Record<string, TopoNode[]> = {}
  layers.forEach(l => { byLayer[l] = [] })
  nodes.forEach(n => {
    if (byLayer[n.layer]) byLayer[n.layer].push(n)
  })

  const positions: Record<string, { x: number; y: number }> = {}
  let y = 20

  const bands: { layer: string; y: number; height: number }[] = []
  const maxRowWidth = MAX_COLS * (NODE_W + NODE_GAP_X)

  for (const layer of layers) {
    const group = byLayer[layer]
    const bandY = y
    y += LAYER_LABEL_H

    const cols = Math.min(group.length, MAX_COLS)
    const rows = Math.ceil(group.length / MAX_COLS) || 1
    const rowWidth = cols * (NODE_W + NODE_GAP_X) - NODE_GAP_X
    const offsetX = (maxRowWidth - rowWidth) / 2

    group.forEach((n, i) => {
      const col = i % MAX_COLS
      const row = Math.floor(i / MAX_COLS)
      positions[n.id] = {
        x: offsetX + col * (NODE_W + NODE_GAP_X),
        y: y + row * (NODE_H + NODE_GAP_Y),
      }
    })

    const layerHeight = LAYER_LABEL_H + rows * (NODE_H + NODE_GAP_Y) + LAYER_PAD_Y
    bands.push({ layer, y: bandY, height: layerHeight })
    y = bandY + layerHeight
  }

  return { positions, bands, width: maxRowWidth + 40, height: y + 20 }
}

function resolveEdges(nodes: TopoNode[], nameMap: Record<string, string>) {
  const edges: { from: string; to: string }[] = []
  const seen = new Set<string>()
  for (const n of nodes) {
    for (const target of n.connectedTo) {
      const toId = nameMap[target.toLowerCase()]
      if (!toId || toId === n.id) continue
      const key = [n.id, toId].sort().join('|')
      if (seen.has(key)) continue
      seen.add(key)
      edges.push({ from: n.id, to: toId })
    }
  }
  return edges
}

const PATCH_COLORS: Record<string, string> = {
  CURRENT: 'var(--risk-low)',
  BEHIND: 'var(--risk-med)',
  END_OF_LIFE: 'var(--risk-crit)',
  NOT_PATCHABLE: 'var(--text-secondary)',
  VENDOR_ONLY: 'var(--risk-med)',
}

export default function Topology() {
  const [model, setModel] = useState<LayerModel>('enterprise')
  const [search, setSearch] = useState('')
  const [zoom, setZoom] = useState(1)
  const [hoveredNode, setHoveredNode] = useState<string | null>(null)
  const svgRef = useRef<SVGSVGElement>(null)

  const { data: itAssets = [] } = useQuery({
    queryKey: ['it-assets'],
    queryFn: () => api.get<ITAsset[]>('/it-assets'),
  })

  const { data: otAssets = [] } = useQuery({
    queryKey: ['ot-assets'],
    queryFn: () => api.get<OTAsset[]>('/ot-assets'),
  })

  const layers = model === 'purdue' ? PURDUE_LAYERS : ENTERPRISE_LAYERS
  const labels = model === 'purdue' ? PURDUE_LABELS : ENTERPRISE_LABELS

  const allNodes = useMemo(() => {
    const itNodes = itAssets.map(itToNode)
    const otNodes = otAssets.map(otToNode)
    if (model === 'purdue') return otNodes
    return itNodes
  }, [itAssets, otAssets, model])

  const filtered = useMemo(() => {
    if (!search) return allNodes
    const q = search.toLowerCase()
    return allNodes.filter(n =>
      n.name.toLowerCase().includes(q) ||
      n.ip.toLowerCase().includes(q) ||
      n.vendor.toLowerCase().includes(q)
    )
  }, [allNodes, search])

  const nameMap = useMemo(() => {
    const m: Record<string, string> = {}
    allNodes.forEach(n => { m[n.name.toLowerCase()] = n.id })
    return m
  }, [allNodes])

  const { positions, bands, width, height } = useMemo(() => buildLayout(filtered, layers), [filtered, layers])
  const edges = useMemo(() => resolveEdges(filtered, nameMap), [filtered, nameMap])

  const neighbors = useMemo(() => {
    if (!hoveredNode) return new Set<string>()
    const s = new Set<string>([hoveredNode])
    edges.forEach(e => {
      if (e.from === hoveredNode) s.add(e.to)
      if (e.to === hoveredNode) s.add(e.from)
    })
    return s
  }, [hoveredNode, edges])

  const handleZoom = useCallback((delta: number) => {
    setZoom(z => Math.max(0.4, Math.min(2.5, z + delta)))
  }, [])

  useEffect(() => {
    const el = svgRef.current?.parentElement
    if (!el) return
    const handler = (e: WheelEvent) => {
      if (e.ctrlKey || e.metaKey) {
        e.preventDefault()
        handleZoom(e.deltaY > 0 ? -0.1 : 0.1)
      }
    }
    el.addEventListener('wheel', handler, { passive: false })
    return () => el.removeEventListener('wheel', handler)
  }, [handleZoom])

  const exportSvg = useCallback(() => {
    const svg = svgRef.current
    if (!svg) return
    // Inline the computed CSS-variable colors so the standalone file renders
    // outside the app (assessors open it in a browser / Office).
    const clone = svg.cloneNode(true) as SVGSVGElement
    const cs = getComputedStyle(document.documentElement)
    let serialized = new XMLSerializer().serializeToString(clone)
    serialized = serialized.replace(/var\((--[a-z0-9-]+)\)/gi, (_m, name) => cs.getPropertyValue(name).trim() || '#888')
    const blob = new Blob([`<?xml version="1.0" encoding="UTF-8"?>\n${serialized}`], { type: 'image/svg+xml' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `topology-${model}-${new Date().toISOString().slice(0, 10)}.svg`
    a.click()
    URL.revokeObjectURL(url)
  }, [model])

  return (
    <div>
      <div className="flex items-center justify-between mb-4 print:hidden">
        <h2 className="text-xl font-bold text-[var(--text-primary)]">Network Topology</h2>
        <div className="flex items-center gap-3">
          <div className="flex border border-[var(--border)] text-sm">
            <button
              onClick={() => setModel('enterprise')}
              className={`px-3 py-1 ${model === 'enterprise' ? 'bg-[var(--accent)] text-white' : 'bg-[var(--bg-tertiary)] text-[var(--text-secondary)]'}`}
            >
              Enterprise
            </button>
            <button
              onClick={() => setModel('purdue')}
              className={`px-3 py-1 ${model === 'purdue' ? 'bg-[var(--accent)] text-white' : 'bg-[var(--bg-tertiary)] text-[var(--text-secondary)]'}`}
            >
              Purdue (OT)
            </button>
          </div>
          <div className="flex items-center gap-1 border border-[var(--border)]">
            <button onClick={() => handleZoom(-0.1)} className="px-2 py-1 text-[var(--text-secondary)] hover:text-[var(--text-primary)]"><ZoomOut size={14} /></button>
            <span className="text-xs text-[var(--text-secondary)] w-10 text-center">{Math.round(zoom * 100)}%</span>
            <button onClick={() => handleZoom(0.1)} className="px-2 py-1 text-[var(--text-secondary)] hover:text-[var(--text-primary)]"><ZoomIn size={14} /></button>
          </div>
          <button onClick={exportSvg} title="Download SVG"
            className="flex items-center gap-1.5 px-2.5 py-1 border border-[var(--border)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] text-sm">
            <Download size={14} /> SVG
          </button>
          <button onClick={() => window.print()} title="Print"
            className="flex items-center gap-1.5 px-2.5 py-1 border border-[var(--border)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] text-sm">
            <Printer size={14} />
          </button>
        </div>
      </div>

      <div className="flex gap-3 mb-4 items-center">
        <div className="relative flex-1 max-w-xs">
          <Search size={14} className="absolute left-2 top-1/2 -translate-y-1/2 text-[var(--text-secondary)]" />
          <input
            className="w-full text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] pl-7 pr-2 py-1.5"
            placeholder="Search assets..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
        <span className="text-xs text-[var(--text-secondary)]">
          {filtered.length} asset{filtered.length !== 1 ? 's' : ''} · {edges.length} connection{edges.length !== 1 ? 's' : ''}
        </span>
      </div>

      {filtered.length === 0 ? (
        <EmptyState
          icon={Network}
          title="No assets to display"
          description={model === 'purdue' ? 'Add OT assets with Purdue levels to see the topology.' : 'Add IT assets to see the network topology.'}
        />
      ) : (
        <div className="bg-[var(--bg-secondary)] border border-[var(--border)] overflow-auto" style={{ maxHeight: 'calc(100vh - 240px)' }}>
          <svg
            ref={svgRef}
            width={width * zoom}
            height={height * zoom}
            viewBox={`0 0 ${width} ${height}`}
            className="select-none"
          >
            {bands.map(b => (
              <g key={b.layer}>
                <rect
                  x={0} y={b.y} width={width} height={b.height}
                  fill="var(--bg-tertiary)" opacity={0.3}
                  rx={4}
                />
                <text x={12} y={b.y + 18} fontSize={11} fontWeight={600} fill="var(--text-secondary)">
                  {labels[b.layer] || b.layer}
                </text>
              </g>
            ))}

            {edges.map((e, i) => {
              const from = positions[e.from]
              const to = positions[e.to]
              if (!from || !to) return null
              const x1 = from.x + NODE_W / 2
              const y1 = from.y + NODE_H / 2
              const x2 = to.x + NODE_W / 2
              const y2 = to.y + NODE_H / 2
              const midY = (y1 + y2) / 2
              const isHovered = hoveredNode && (neighbors.has(e.from) && neighbors.has(e.to))
              return (
                <path
                  key={i}
                  d={`M ${x1} ${y1} C ${x1} ${midY}, ${x2} ${midY}, ${x2} ${y2}`}
                  fill="none"
                  stroke={isHovered ? 'var(--accent)' : 'var(--border)'}
                  strokeWidth={isHovered ? 2 : 1}
                  opacity={hoveredNode && !isHovered ? 0.15 : 0.6}
                />
              )
            })}

            {filtered.map(n => {
              const pos = positions[n.id]
              if (!pos) return null
              const dimmed = hoveredNode && !neighbors.has(n.id)
              const borderColor = PATCH_COLORS[n.patchStatus] || 'var(--border)'
              return (
                <g
                  key={n.id}
                  transform={`translate(${pos.x}, ${pos.y})`}
                  opacity={dimmed ? 0.2 : 1}
                  onMouseEnter={() => setHoveredNode(n.id)}
                  onMouseLeave={() => setHoveredNode(null)}
                  style={{ cursor: 'pointer' }}
                >
                  <rect
                    width={NODE_W} height={NODE_H} rx={4}
                    fill="var(--bg-primary)"
                    stroke={borderColor}
                    strokeWidth={hoveredNode === n.id ? 2 : 1}
                  />
                  {n.type === 'ot' && (
                    <circle cx={NODE_W - 6} cy={6} r={4} fill="var(--risk-med)" />
                  )}
                  <text x={8} y={18} fontSize={11} fontWeight={600} fill="var(--text-primary)">
                    {n.name.length > 16 ? n.name.slice(0, 15) + '…' : n.name}
                  </text>
                  <text x={8} y={32} fontSize={9} fill="var(--text-secondary)">
                    {n.ip || n.role.replace(/_/g, ' ')}
                  </text>
                  <text x={8} y={42} fontSize={8} fill="var(--text-tertiary)">
                    {n.vendor}
                  </text>
                </g>
              )
            })}
          </svg>
        </div>
      )}
    </div>
  )
}
