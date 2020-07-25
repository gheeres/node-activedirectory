'use strict'

const tap = require('tap')
const utilities = require('../lib/components/utilities')

tap.test('Utility functions', t => {
  t.test('parseDistinguishedName', t => {
    t.test('handling commas which are no component separators inside DNs', t => {
      const input = 'CN=Doe\\, John (Test),OU=Technicians,OU=Users,OU=Local Resources,OU=DEDUS,DC=abc,DC=dom'
      const output = utilities.parseDistinguishedName(input)
      t.equal(output, 'CN=Doe\\\\, John \\\\28Test\\\\29,OU=Technicians,OU=Users,OU=Local Resources,OU=DEDUS,DC=abc,DC=dom')
      t.end()
    })

    t.test('characters to be escaped inside DNs', t => {
      const input = 'CN= Max Mustermann*,OU=Test (12345),OU=Users,OU=Local Resources,OU=DEDUS,DC=abc,DC=dom'
      const output = utilities.parseDistinguishedName(input)
      t.equal(output, 'CN=\\ Max Mustermann\\\\2A,OU=Test \\\\2812345\\\\29,OU=Users,OU=Local Resources,OU=DEDUS,DC=abc,DC=dom')
      t.end()
    })

    t.end()
  })

  t.end()
})
