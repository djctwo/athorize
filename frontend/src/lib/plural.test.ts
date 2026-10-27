import { describe, expect, it } from 'vitest'
import { plural } from './plural'

describe('plural', () => {
  it('uses the singular only for exactly one', () => {
    expect(plural(1, 'item')).toBe('1 item')
    expect(plural(0, 'item')).toBe('0 items')
    expect(plural(2, 'item')).toBe('2 items')
  })
  it('takes an irregular plural form', () => {
    expect(plural(1, 'entry', 'entries')).toBe('1 entry')
    expect(plural(4, 'entry', 'entries')).toBe('4 entries')
  })
})
