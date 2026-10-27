import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import RiskMatrix from './RiskMatrix'
import type { RiskRegisterEntry } from '../types'

const risk = (likelihood: string, impact: string, status = 'OPEN') =>
  ({ likelihood, impact, status } as RiskRegisterEntry)

describe('RiskMatrix', () => {
  it('counts active risks per cell and titles cells with the backend risk level', () => {
    render(<RiskMatrix risks={[
      risk('HIGH', 'HIGH'),
      risk('HIGH', 'HIGH'),
      risk('LOW', 'LOW'),
    ]} />)
    // HIGH×HIGH = VERY_HIGH cell with count 2
    const veryHigh = screen.getByTitle(/Very High — likelihood high × impact high/)
    expect(veryHigh).toHaveTextContent('2')
    const lowCell = screen.getByTitle(/^Low — likelihood low × impact low/)
    expect(lowCell).toHaveTextContent('1')
  })

  it('excludes CLOSED risks and reports unscored ones', () => {
    render(<RiskMatrix risks={[
      risk('HIGH', 'HIGH', 'CLOSED'),          // must not count
      risk('WEIRD', 'HIGH'),                    // unscorable vocab
    ]} />)
    const veryHigh = screen.getByTitle(/Very High — likelihood high × impact high/)
    expect(veryHigh).toHaveTextContent(/^\(?0?\)?$|^$/) // empty cell (no count rendered)
    expect(screen.getByText('1 unscored')).toBeInTheDocument()
  })

  it('mirrors the backend matrix semantics on the diagonal', () => {
    render(<RiskMatrix risks={[]} />)
    expect(screen.getByTitle(/^Low — likelihood low × impact low/)).toBeInTheDocument()
    expect(screen.getByTitle(/^Moderate — likelihood moderate × impact moderate/)).toBeInTheDocument()
    expect(screen.getByTitle(/^Very High — likelihood high × impact high/)).toBeInTheDocument()
    // asymmetric off-diagonal: low likelihood × high impact = MODERATE
    expect(screen.getByTitle(/^Moderate — likelihood low × impact high/)).toBeInTheDocument()
  })

  it('cells are buttons and fire onCellClick with (likelihood, impact)', () => {
    const onClick = vi.fn()
    render(<RiskMatrix risks={[risk('MODERATE', 'HIGH')]} onCellClick={onClick} />)
    fireEvent.click(screen.getByTitle(/High — likelihood moderate × impact high/))
    expect(onClick).toHaveBeenCalledWith('MODERATE', 'HIGH')
  })

  it('renders a static grid (no buttons) without onCellClick', () => {
    render(<RiskMatrix risks={[]} />)
    expect(screen.queryAllByRole('button')).toHaveLength(0)
  })
})
