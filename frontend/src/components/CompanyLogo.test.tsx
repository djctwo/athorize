import { describe, expect, it } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import CompanyLogo from './CompanyLogo'

const URI = 'data:image/png;base64,iVBORw0KGgo='

describe('CompanyLogo', () => {
  it('renders the logo image from the data URI', () => {
    render(<CompanyLogo src={URI} name="Acme Corp" />)
    const img = screen.getByAltText('Acme Corp logo')
    expect(img).toBeInTheDocument()
    expect(img).toHaveAttribute('src', URI)
  })

  it('renders nothing without a logo (graceful text-only fallback)', () => {
    const { container } = render(<CompanyLogo src={null} name="Acme Corp" />)
    expect(container).toBeEmptyDOMElement()
  })

  it('hides itself when the image fails to load', () => {
    const { container } = render(<CompanyLogo src={URI} name="Acme Corp" />)
    fireEvent.error(screen.getByAltText('Acme Corp logo'))
    expect(container).toBeEmptyDOMElement()
  })

  it('uses a generic alt when the company name is unknown', () => {
    render(<CompanyLogo src={URI} />)
    expect(screen.getByAltText('Company logo')).toBeInTheDocument()
  })
})
