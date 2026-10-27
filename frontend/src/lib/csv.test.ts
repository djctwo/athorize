import { describe, expect, it } from 'vitest'
import { parseControlsCsv, parseCsv } from './csv'

describe('Framework Builder CSV import (IMPORTS-27)', () => {
  it('keeps commas and newlines inside quoted fields', () => {
    const text = [
      'id,family,family_name,title,description',
      'POL-1,POL,Policy,"Acceptable use, remote work",Staff must sign the AUP',
      'KEY-1,KEY,Keys,Key escrow,"Keys are generated in the HSM.',
      'Keys escrowed."',
    ].join('\n')
    expect(parseControlsCsv(text)).toEqual([
      { id: 'POL-1', family: 'POL', family_name: 'Policy', title: 'Acceptable use, remote work',
        description: 'Staff must sign the AUP' },
      { id: 'KEY-1', family: 'KEY', family_name: 'Keys', title: 'Key escrow',
        description: 'Keys are generated in the HSM.\nKeys escrowed.' },
    ])
  })

  it('handles doubled quotes, CRLF line endings, a BOM and blank lines', () => {
    expect(parseCsv('﻿a,"say ""hi"""\r\n\r\nb,c\r\n')).toEqual([['a', 'say "hi"'], ['b', 'c']])
  })

  it('falls back to the id as title and skips rows without an id', () => {
    expect(parseControlsCsv('X-1\n,orphan,row')).toEqual([
      { id: 'X-1', family: '', family_name: '', title: 'X-1', description: '' },
    ])
  })
})
