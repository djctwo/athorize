// Executive Compliance Briefing — PPTX export.
//
// The findings slide is crosswalk-aware: each open finding lists the mapped
// controls in OTHER frameworks that remediation also satisfies, so leadership
// sees one fix paying down multiple framework obligations.
import pptxgen from 'pptxgenjs'
import { api } from './api'
import type { Finding, Framework, System } from '../types'
import { plural } from './plural'
import { splitPairs } from './compliancePairs'

const FONT = 'Calibri'
const C = {
  bg: 'FFFFFF',
  ink: '16161A',
  sub: '5A5A64',
  accent: '7559E0',
  green: '0E8C5A',
  amber: 'B3771B',
  red: 'C14A32',
  line: 'E4E2DD',
  headFill: 'F1F0ED',
}

interface ComplianceScore {
  system_id: number
  system_name: string
  framework_id: string
  score_percentage: number
  total_controls: number
  implemented: number
  open_findings: number
  critical_findings: number
  assessed_controls?: number
  has_work: boolean
}

interface FindingImpact {
  framework_id: string
  control_id: string
  relationship: string
  implementation_status: string | null
}

interface Suggestion {
  framework_id: string
  control_id: string
  source_framework_id?: string
}

interface RedTeamReport {
  id: number
  system_id: number
  framework_id: string
  total_findings: number
  total_exposure_low: number
  total_exposure_high: number
  top5_reduction_low: number
  top5_reduction_high: number
  quick_win_count: number
  has_org_context: number
  created_at: string
}

// Organization-level exposure from GET /redteam/exposure-summary — computed by
// the backend with the SAME probable-loss model + 1.5x revenue cap as a single
// report (services/risk_quantification.summarize_reports). Never re-derived here.
interface ExposureSummary {
  total_exposure_low: number
  total_exposure_high: number
  top5_reduction_low: number
  top5_reduction_high: number
  quick_win_count: number
  report_ids: number[]
  model: string
}

// Counts come from /dashboard/snapshot so the briefing shows exactly the
// Dashboard tiles' numbers (one definition: services/metrics.py).
interface Snapshot {
  organization_name: string
  critical_findings: number
  overdue_findings: number
  expired_evidence: number
}

interface EvidenceItem {
  id: number
  expiration_date: string | null
}

interface RiskItem {
  id: number
  title: string
  risk_level: string | null
  status: string
}

interface CalendarItem {
  id: number
  title: string
  event_type: string
  event_date: string
}

interface Methodology {
  version: string
  last_reviewed: string
  breach_costs_source: string
  penalty_sources: string
  disclaimer: string
  stale: boolean
}

/** "1 critical finding" / "3 critical findings" */
export { plural }

function money(n: number): string {
  if (n >= 1_000_000) return `$${(n / 1_000_000).toFixed(1)}M`
  if (n >= 1_000) return `$${Math.round(n / 1_000)}K`
  return `$${n}`
}


function sevColor(sev: string): string {
  if (sev === 'CRITICAL') return C.red
  if (sev === 'HIGH') return C.amber
  return C.sub
}

function header(slide: pptxgen.Slide, title: string, subtitle: string): void {
  slide.addText(title, {
    x: 0.55, y: 0.45, w: 12.2, h: 0.55,
    fontFace: FONT, fontSize: 24, bold: true, color: C.ink,
  })
  slide.addText(subtitle, {
    x: 0.55, y: 1.0, w: 12.2, h: 0.35,
    fontFace: FONT, fontSize: 12, color: C.sub,
  })
  slide.addShape('line', { x: 0.55, y: 1.42, w: 12.2, h: 0, line: { color: C.accent, width: 1.5 } })
}

/** The Reports page System / Framework filters. Empty = the whole company. */
export interface BriefingScope {
  systemId?: number | null
  frameworkId?: string | null
}

/** `path` plus only the filters that are set (unfiltered paths stay exactly as before). */
function withScope(path: string, params: Record<string, string | number | null | undefined>): string {
  const q = Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== '')
    .map(([k, v]) => `${k}=${encodeURIComponent(String(v))}`).join('&')
  if (!q) return path
  return `${path}${path.includes('?') ? '&' : '?'}${q}`
}

export async function generateExecBriefing(scope: BriefingScope = {}): Promise<void> {
  const systemId = scope.systemId || undefined
  const frameworkId = scope.frameworkId || undefined
  const filtered = !!(systemId || frameworkId)
  const sysQ = { system_id: systemId }
  const bothQ = { system_id: systemId, framework_id: frameworkId }
  // Gather everything up front, already narrowed to the selected system / framework.
  const [allSystems, frameworks, allScores, findings, snapshot, redteam, evidence, risks, calendar] = await Promise.all([
    api.get<System[]>('/systems'),
    api.get<Framework[]>('/frameworks'),
    api.get<ComplianceScore[]>(withScope('/dashboard/compliance', sysQ)),
    api.get<Finding[]>(withScope('/findings', bothQ)),
    api.get<Snapshot>(withScope('/dashboard/snapshot', bothQ)),
    api.get<RedTeamReport[]>(withScope('/redteam', bothQ)).catch(() => [] as RedTeamReport[]),
    api.get<EvidenceItem[]>(withScope('/evidence', bothQ)).catch(() => [] as EvidenceItem[]),
    api.get<RiskItem[]>(withScope('/risks', sysQ)).catch(() => [] as RiskItem[]),
    // Manual events only: derived deadlines (findings, evidence…) have their own slides.
    api.get<CalendarItem[]>(withScope('/calendar?derived=false', bothQ)).catch(() => [] as CalendarItem[]),
  ])
  const systems = systemId ? allSystems.filter(x => x.id === systemId) : allSystems
  // Rows for systems x frameworks nobody has started (0%, no findings) are noise
  // to leadership: leave them out and say how many were left out.
  const { shown: scores, hidden: hiddenPairs } = splitPairs(
    allScores.filter(sc => sc.total_controls > 0 && (!frameworkId || sc.framework_id === frameworkId)),
  )
  const exposure = await api
    .get<ExposureSummary>(withScope('/redteam/exposure-summary', bothQ))
    .catch(() => undefined)
  const methodology = await api
    .get<{ methodology?: Methodology }>('/redteam/risk-context')
    .then(r => r.methodology)
    .catch(() => undefined)
  const orgName = snapshot.organization_name || 'Compliance Program'
  const fwName = (id: string) => frameworks.find(f => f.id === id)?.short_name || id
  const openFindings = findings
    // Open = the server's is_open (services/metrics.py), as on every page.
    .filter(f => f.is_open)
    .sort((a, b) => {
      const rank: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }
      return (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9)
    })
    .slice(0, 14)

  const impacts = new Map<number, FindingImpact[]>()
  await Promise.all(openFindings.map(async f => {
    try {
      const r = await api.get<{ impacts: FindingImpact[] }>(`/crosswalk/findings/${f.id}`)
      impacts.set(f.id, r.impacts)
    } catch {
      impacts.set(f.id, [])
    }
  }))

  const suggestionCounts = new Map<number, Suggestion[]>()
  await Promise.all(systems.map(async s => {
    try {
      const r = await api.get<{ suggestions: Suggestion[] }>(`/crosswalk/suggestions?system_id=${s.id}`)
      // With a framework selected: only suggestions into or out of it.
      suggestionCounts.set(s.id, frameworkId
        ? r.suggestions.filter(x => x.framework_id === frameworkId || x.source_framework_id === frameworkId)
        : r.suggestions)
    } catch {
      suggestionCounts.set(s.id, [])
    }
  }))

  // Narrative metrics
  const today = new Date().toLocaleDateString('en-CA')
  // Per-report table rows: the reports the backend summary was built from
  // (latest per system x framework).
  const summaryIds = new Set(exposure?.report_ids ?? [])
  const latestReports = redteam.filter(r => summaryIds.has(r.id))
  const exposureLow = exposure?.total_exposure_low ?? 0
  const exposureHigh = exposure?.total_exposure_high ?? 0
  const top5Low = exposure?.top5_reduction_low ?? 0
  const top5High = exposure?.top5_reduction_high ?? 0
  const quickWins = exposure?.quick_win_count ?? 0

  const criticalCount = snapshot.critical_findings ?? 0
  const overdueCount = snapshot.overdue_findings ?? 0
  const expiredCount = snapshot.expired_evidence ?? 0
  const in90 = new Date(Date.now() + 90 * 86400000).toLocaleDateString('en-CA')
  const expiringEvidence = evidence.filter(e => e.expiration_date && e.expiration_date >= today && e.expiration_date <= in90)
  const highRisks = risks.filter(r => (r.risk_level === 'HIGH' || r.risk_level === 'VERY_HIGH') && r.status !== 'CLOSED')
  const upcoming = calendar
    .filter(c => c.event_date >= today && c.event_date <= in90)
    .sort((a, b) => a.event_date.localeCompare(b.event_date))
  const totalSuggestions = [...suggestionCounts.values()].reduce((a, b) => a + b.length, 0)
  const suggestionFrameworks = new Set(
    [...suggestionCounts.values()].flat().map(x => x.framework_id),
  )
  const multiImpactCount = openFindings.filter(f => {
    const fws = new Set((impacts.get(f.id) ?? []).map(i => i.framework_id))
    return fws.size >= 2
  }).length

  const pres = new pptxgen()
  pres.defineLayout({ name: 'WIDE', width: 13.333, height: 7.5 })
  pres.layout = 'WIDE'

  // ---- Title ----
  {
    const s = pres.addSlide()
    s.background = { color: C.bg }
    s.addText('Executive Compliance Briefing', {
      x: 0.8, y: 2.5, w: 11.7, h: 0.9,
      fontFace: FONT, fontSize: 36, bold: true, color: C.ink,
    })
    s.addText(orgName, {
      x: 0.8, y: 3.4, w: 11.7, h: 0.5,
      fontFace: FONT, fontSize: 18, color: C.accent, bold: true,
    })
    const activeFw = frameworks.filter(f => f.is_active)
    const scopeLine = filtered
      ? `Scope: ${systemId ? systems.map(x => `${x.acronym} — ${x.name}`).join(', ') : 'all systems'} · ${frameworkId ? fwName(frameworkId) : 'all frameworks'}`
      : `${plural(systems.length, 'system')} · ${plural(activeFw.length, 'active framework')}`
    s.addText(
      `${scopeLine} · generated ${new Date().toLocaleDateString('en-CA')}`,
      { x: 0.8, y: 4.0, w: 11.7, h: 0.4, fontFace: FONT, fontSize: 13, color: C.sub },
    )
  }

  // ---- Compliance posture ---- (left out of a filtered deck with nothing to show)
  if (!(filtered && scores.length === 0)) {
    const s = pres.addSlide()
    s.background = { color: C.bg }
    header(s, 'Where We Stand', 'Compliance posture — score per system per active framework')
    const head = [
      { text: 'System', options: { bold: true, fill: { color: C.headFill } } },
      { text: 'Framework', options: { bold: true, fill: { color: C.headFill } } },
      { text: 'Score', options: { bold: true, fill: { color: C.headFill } } },
      { text: 'Implemented', options: { bold: true, fill: { color: C.headFill } } },
      { text: 'Open Findings', options: { bold: true, fill: { color: C.headFill } } },
      { text: 'Critical', options: { bold: true, fill: { color: C.headFill } } },
    ]
    const rows = scores
      .map(sc => [
        { text: sc.system_name },
        { text: fwName(sc.framework_id) },
        {
          text: `${sc.score_percentage.toFixed(1)}%`,
          options: { bold: true, color: sc.score_percentage >= 80 ? C.green : sc.score_percentage >= 50 ? C.amber : C.red },
        },
        { text: `${sc.implemented}/${sc.total_controls}` },
        { text: String(sc.open_findings) },
        { text: String(sc.critical_findings), options: sc.critical_findings > 0 ? { color: C.red, bold: true } : {} },
      ])
    s.addTable([head, ...rows], {
      x: 0.55, y: 1.7, w: 12.2,
      fontFace: FONT, fontSize: 11, color: C.ink,
      border: { type: 'solid', color: C.line, pt: 0.5 },
      autoPage: true, autoPageRepeatHeader: true,
    })
    if (hiddenPairs > 0) {
      s.addText(
        `${plural(hiddenPairs, 'system × framework pair')} not started yet (no control assessed, no open finding) ${hiddenPairs === 1 ? 'is' : 'are'} left out.`,
        { x: 0.55, y: 6.85, w: 12.2, h: 0.4, fontFace: FONT, fontSize: 10, italic: true, color: C.sub },
      )
    }
  }

  // ---- Risk exposure ($) ----
  // Always present (R2USER-17): before any Red Team run the deck pointed at an
  // "exposure slide" that did not exist. Without a run it says how to get one.
  // A filtered deck with no Red Team run in scope leaves the slide out instead.
  const hasExposure = latestReports.length > 0 && exposureHigh > 0
  const exposureSlide = hasExposure || !filtered
  if (!hasExposure && !filtered) {
    const s = pres.addSlide()
    s.background = { color: C.bg }
    header(s, 'What the Gaps Cost', 'Estimated financial exposure from current compliance gaps')
    s.addText(
      'Not priced yet: no Red Team analysis has been run for these systems. Run Red Team (Red Team page → a system and framework) ' +
      'to estimate the dollar exposure of the open gaps and what fixing the top five would save; re-generate this briefing ' +
      'and this slide fills in.',
      { x: 0.7, y: 2.0, w: 11.9, h: 1.4, fontFace: FONT, fontSize: 16, color: C.ink, valign: 'top' },
    )
    s.addShape('rect', { x: 0.7, y: 3.8, w: 2.9, h: 1.8, fill: { color: C.headFill }, line: { color: C.line, width: 0.75 } })
    s.addText(String(criticalCount), { x: 0.7, y: 4.05, w: 2.9, h: 0.8, align: 'center', fontFace: FONT, fontSize: 22, bold: true, color: criticalCount > 0 ? C.red : C.green })
    s.addText('Open Critical Findings', { x: 0.7, y: 4.9, w: 2.9, h: 0.5, align: 'center', fontFace: FONT, fontSize: 11, color: C.sub })
  } else if (hasExposure) {
    const s = pres.addSlide()
    s.background = { color: C.bg }
    header(s, 'What the Gaps Cost', 'Estimated financial exposure from current compliance gaps — adversarial analysis, calibrated to this organization')
    const kpis: Array<[string, string, string]> = [
      ['Estimated Exposure', `${money(exposureLow)} – ${money(exposureHigh)}`, C.red],
      ['Fixing Each Report\'s Top 5 Saves (est.)', `${money(top5Low)} – ${money(top5High)}`, C.green],
      ['Quick Wins Available', String(quickWins), C.accent],
      ['Open Critical Findings', String(criticalCount), criticalCount > 0 ? C.red : C.green],
    ]
    kpis.forEach(([label, value, color], i) => {
      const x = 0.55 + i * 3.1
      s.addShape('rect', { x, y: 2.0, w: 2.9, h: 1.8, fill: { color: C.headFill }, line: { color: C.line, width: 0.75 } })
      s.addText(value, { x, y: 2.25, w: 2.9, h: 0.8, align: 'center', fontFace: FONT, fontSize: 22, bold: true, color })
      s.addText(label, { x, y: 3.1, w: 2.9, h: 0.5, align: 'center', fontFace: FONT, fontSize: 11, color: C.sub })
    })
    const rows = latestReports.map(r => {
      const sys = systems.find(x => x.id === r.system_id)
      return [
        { text: sys ? `${sys.acronym} — ${sys.name}` : String(r.system_id) },
        { text: fwName(r.framework_id) },
        { text: String(r.total_findings) },
        { text: `${money(r.total_exposure_low)} – ${money(r.total_exposure_high)}`, options: { bold: true, color: C.red } },
        { text: String(r.quick_win_count) },
      ]
    })
    s.addTable([
      [
        { text: 'System', options: { bold: true, fill: { color: C.headFill } } },
        { text: 'Framework', options: { bold: true, fill: { color: C.headFill } } },
        { text: 'Findings', options: { bold: true, fill: { color: C.headFill } } },
        { text: 'Exposure', options: { bold: true, fill: { color: C.headFill } } },
        { text: 'Quick Wins', options: { bold: true, fill: { color: C.headFill } } },
      ],
      ...rows,
    ], {
      x: 0.55, y: 4.3, w: 12.2,
      fontFace: FONT, fontSize: 11, color: C.ink,
      border: { type: 'solid', color: C.line, pt: 0.5 },
    })
    if (methodology) {
      s.addText(
        `Estimates, not actuals. Breach costs: ${methodology.breach_costs_source}. Regulatory penalties: ${methodology.penalty_sources}. ` +
        `Figures are weighted by severity and organization context (benchmarks v${methodology.version}, reviewed ${methodology.last_reviewed}). ${exposure?.model ?? ''} ${methodology.disclaimer}`,
        { x: 0.55, y: 6.55, w: 12.2, h: 0.8, fontFace: FONT, fontSize: 8.5, italic: true, color: C.sub },
      )
    }
  }

  // ---- Open findings with crosswalk remediation ----
  if (!(filtered && openFindings.length === 0)) {
    const s = pres.addSlide()
    s.background = { color: C.bg }
    header(
      s,
      'What Threatens It — Open Findings',
      'Each fix closes the finding AND satisfies the mapped requirements in every framework listed — remediate once, comply many',
    )
    const head = [
      { text: 'Sev', options: { bold: true, fill: { color: C.headFill } } },
      { text: 'Finding', options: { bold: true, fill: { color: C.headFill } } },
      { text: 'System', options: { bold: true, fill: { color: C.headFill } } },
      { text: 'Control to Apply', options: { bold: true, fill: { color: C.headFill } } },
      { text: 'Also Satisfies When Fixed', options: { bold: true, fill: { color: C.headFill } } },
    ]
    const sysName = (id: number) => systems.find(x => x.id === id)?.acronym ?? String(id)
    const rows = openFindings.map(f => {
      const imp = impacts.get(f.id) ?? []
      const byFw = new Map<string, string[]>()
      for (const i of imp) {
        const list = byFw.get(i.framework_id) ?? []
        list.push(i.control_id)
        byFw.set(i.framework_id, list)
      }
      const alsoSatisfies = [...byFw.entries()]
        .map(([fw, ctrls]) => `${fwName(fw)}: ${ctrls.join(', ')}`)
        .join('  ·  ')
      return [
        { text: f.severity, options: { color: sevColor(f.severity), bold: true } },
        { text: f.title },
        { text: sysName(f.system_id) },
        { text: f.control_id ? `${f.control_id} (${fwName(f.framework_id)})` : '—' },
        { text: alsoSatisfies || '—', options: { color: alsoSatisfies ? C.ink : C.sub } },
      ]
    })
    s.addTable([head, ...rows], {
      x: 0.55, y: 1.7, w: 12.2,
      colW: [0.9, 3.6, 0.9, 2.4, 4.4],
      fontFace: FONT, fontSize: 10, color: C.ink,
      border: { type: 'solid', color: C.line, pt: 0.5 },
      autoPage: true, autoPageRepeatHeader: true,
    })
  }

  // ---- Crosswalk leverage ----
  if (!(filtered && totalSuggestions === 0)) {
    const s = pres.addSlide()
    s.background = { color: C.bg }
    header(
      s,
      'What We Already Own — Crosswalk Leverage',
      'Implementations already paid for that can be claimed in other frameworks (pending assessor review)',
    )
    const head = [
      { text: 'System', options: { bold: true, fill: { color: C.headFill } } },
      { text: 'Ready to Claim', options: { bold: true, fill: { color: C.headFill } } },
      { text: 'Frameworks', options: { bold: true, fill: { color: C.headFill } } },
    ]
    const rows = systems.map(sys => {
      const sugs = suggestionCounts.get(sys.id) ?? []
      const fws = [...new Set(sugs.map(x => fwName(x.framework_id)))]
      return [
        { text: `${sys.acronym} — ${sys.name}` },
        { text: String(sugs.length), options: sugs.length > 0 ? { bold: true, color: C.accent } : {} },
        { text: fws.join(', ') || '—' },
      ]
    })
    s.addTable([head, ...rows], {
      x: 0.55, y: 1.7, w: 12.2,
      fontFace: FONT, fontSize: 12, color: C.ink,
      border: { type: 'solid', color: C.line, pt: 0.5 },
    })
    const total = [...suggestionCounts.values()].reduce((a, b) => a + b.length, 0)
    s.addText(
      `${plural(total, 'control implementation')} ${total === 1 ? 'is' : 'are'} one review away from counting in additional frameworks — see the Crosswalk page.`,
      { x: 0.55, y: 6.4, w: 12.2, h: 0.5, fontFace: FONT, fontSize: 12, italic: true, color: C.sub },
    )
  }

  // ---- Program health ----
  {
    const s = pres.addSlide()
    s.background = { color: C.bg }
    header(s, 'Program Health', 'Operational readiness behind the scores — evidence, deadlines, and risk discipline')
    const kpis: Array<[string, string, string]> = [
      ['Overdue Findings', String(overdueCount), overdueCount > 0 ? C.red : C.green],
      ['Expired Evidence', String(expiredCount), expiredCount > 0 ? C.red : C.green],
      ['Evidence Expiring ≤ 90d', String(expiringEvidence.length), expiringEvidence.length > 0 ? C.amber : C.green],
      ['High / Very High Risks', String(highRisks.length), highRisks.length > 0 ? C.amber : C.green],
    ]
    kpis.forEach(([label, value, color], i) => {
      const x = 0.55 + i * 3.1
      s.addShape('rect', { x, y: 1.9, w: 2.9, h: 1.6, fill: { color: C.headFill }, line: { color: C.line, width: 0.75 } })
      s.addText(value, { x, y: 2.1, w: 2.9, h: 0.7, align: 'center', fontFace: FONT, fontSize: 24, bold: true, color })
      s.addText(label, { x, y: 2.85, w: 2.9, h: 0.5, align: 'center', fontFace: FONT, fontSize: 11, color: C.sub })
    })
    if (upcoming.length > 0) {
      s.addText('Next 90 days', { x: 0.55, y: 3.9, w: 12.2, h: 0.4, fontFace: FONT, fontSize: 14, bold: true, color: C.ink })
      const rows = upcoming.slice(0, 6).map(e => [
        { text: e.event_date },
        { text: e.event_type },
        { text: e.title },
      ])
      s.addTable([
        [
          { text: 'Date', options: { bold: true, fill: { color: C.headFill } } },
          { text: 'Type', options: { bold: true, fill: { color: C.headFill } } },
          { text: 'Event', options: { bold: true, fill: { color: C.headFill } } },
        ],
        ...rows,
      ], {
        x: 0.55, y: 4.35, w: 12.2, colW: [1.6, 2.0, 8.6],
        fontFace: FONT, fontSize: 11, color: C.ink,
        border: { type: 'solid', color: C.line, pt: 0.5 },
      })
    }
  }

  // ---- Way forward (30/60/90) ----
  {
    const s = pres.addSlide()
    s.background = { color: C.bg }
    header(s, 'Way Forward', 'A 30 / 60 / 90-day path generated from the data in this briefing')
    const cols: Array<[string, string, string[]]> = [
      ['Next 30 days', C.red, [
        criticalCount > 0 ? `Remediate ${criticalCount} critical finding${criticalCount === 1 ? '' : 's'} — each closes requirements in multiple frameworks (see crosswalk column)` : 'No critical findings open — hold the line',
        overdueCount > 0 ? `Clear ${overdueCount} overdue finding${overdueCount === 1 ? '' : 's'} before they surface in an assessment` : 'No overdue findings',
        expiredCount > 0 ? `Refresh ${expiredCount} expired evidence artifact${expiredCount === 1 ? '' : 's'}` : 'Evidence vault is current',
      ]],
      ['Next 60 days', C.amber, [
        quickWins > 0 ? `Execute the ${plural(quickWins, 'red-team quick win')} — low effort, highest ROI per dollar` : 'Re-run red team analysis after 30-day fixes land',
        totalSuggestions > 0 ? `Review the ${plural(totalSuggestions, 'crosswalk-suggested implementation')} — claimable across ${suggestionFrameworks.size} framework${suggestionFrameworks.size === 1 ? '' : 's'} from work already done` : 'Crosswalk queue is clear',
        expiringEvidence.length > 0 ? `Re-collect the ${plural(expiringEvidence.length, 'artifact')} expiring within 90 days` : 'No evidence expiring soon',
      ]],
      ['Next 90 days', C.green, [
        upcoming.length > 0 ? `Prepare for: ${upcoming.slice(0, 2).map(e => e.title).join('; ')}` : 'No scheduled assessments — schedule the next one',
        highRisks.length > 0 ? `Drive treatment on ${highRisks.length} high/very-high risks` : 'Risk register under control',
        'Re-run this briefing and compare exposure trend',
      ]],
    ]
    cols.forEach(([title, color, items], i) => {
      const x = 0.55 + i * 4.15
      s.addShape('rect', { x, y: 1.8, w: 3.95, h: 0.5, fill: { color }, line: { type: 'none' } })
      s.addText(title, { x, y: 1.8, w: 3.95, h: 0.5, align: 'center', valign: 'middle', fontFace: FONT, fontSize: 14, bold: true, color: 'FFFFFF' })
      s.addText(
        items.map(t => ({ text: t, options: { bullet: { characterCode: '2022', indent: 10 }, breakLine: true, paraSpaceAfter: 8 } })),
        { x, y: 2.45, w: 3.95, h: 4.4, fontFace: FONT, fontSize: 12, color: C.ink, valign: 'top' },
      )
    })
  }

  // ---- Recommendations ----
  {
    const s = pres.addSlide()
    s.background = { color: C.bg }
    header(s, 'Recommendations', 'The ask — specific, sequenced, and measurable')
    const recs: string[] = []
    if (criticalCount > 0) {
      recs.push(`Authorize immediate remediation of the ${plural(criticalCount, 'critical finding')}. The crosswalk shows each fix also satisfies mapped requirements in other frameworks — ${multiImpactCount} of the top findings ${multiImpactCount === 1 ? 'pays' : 'pay'} down two or more frameworks at once.`)
    }
    if (exposureHigh > 0) {
      recs.push(`Fund the top-5 red team fixes in each report: estimated exposure reduction of ${money(top5Low)}–${money(top5High)} against a current exposure of ${money(exposureLow)}–${money(exposureHigh)}.`)
    }
    if (totalSuggestions > 0) {
      recs.push(`Assign an assessor to the Crosswalk Review queue: ${plural(totalSuggestions, 'implementation')} already paid for ${totalSuggestions === 1 ? 'is' : 'are'} one review away from counting in ${suggestionFrameworks.size === 1 ? 'another framework' : `${suggestionFrameworks.size} more frameworks`} — the cheapest compliance gain available.`)
    }
    if (expiredCount > 0 || expiringEvidence.length > 0) {
      recs.push(`Re-establish the evidence collection cadence: ${expiredCount} expired and ${plural(expiringEvidence.length, 'expiring artifact')} put otherwise-implemented controls at audit risk.`)
    }
    if (upcoming.length > 0) {
      recs.push(`Lock the preparation plan for ${upcoming[0].title} (${upcoming[0].event_date}) now — readiness work above directly feeds it.`)
    }
    recs.push('Re-run this briefing monthly; exposure, posture, and the crosswalk queue are the trend lines that show the program working.')
    s.addText(
      recs.map((t, i) => ({
        text: `${i + 1}.  ${t}`,
        options: { breakLine: true, paraSpaceAfter: 14 },
      })),
      { x: 0.7, y: 1.9, w: 11.9, h: 5.0, fontFace: FONT, fontSize: 14, color: C.ink, valign: 'top' },
    )
    if (methodology && exposureSlide) {
      s.addText(
        `Monetary figures are planning estimates (${methodology.breach_costs_source}; published penalty structures). See the exposure slide for full methodology.`,
        { x: 0.7, y: 6.85, w: 11.9, h: 0.4, fontFace: FONT, fontSize: 8.5, italic: true, color: C.sub },
      )
    }
  }

  await pres.writeFile({ fileName: `executive-briefing-${new Date().toLocaleDateString('en-CA')}.pptx` })
}
