'use strict'

const tap = require('tap')
const RangeAttribute = require('./../lib/client/RangeAttribute')

tap.test('Range Attribute Class', t => {
  t.test('should return determine if ranges are present', t => {
    let attrs = {}
    let hasRanges = RangeAttribute.hasRangeAttributes(attrs)
    t.false(hasRanges)

    attrs = {
      'member;range=0-5': {}
    }
    hasRanges = RangeAttribute.hasRangeAttributes(attrs)
    t.true(hasRanges)

    t.end()
  })

  t.test('should parse an attribute string with a range', t => {
    const attr = 'member;range=0-5'
    const rrsa = RangeAttribute(attr)
    t.equal(rrsa.attributeName, 'member')
    t.equal(rrsa.low, 0)
    t.equal(rrsa.high, 5)
    t.end()
  })

  t.test('should parse multiple range attributes', t => {
    const attrs = {
      'member;range=0-5': {},
      'foo;range=100-200': {}
    }
    const ranges = RangeAttribute.getRangeAttributes(attrs)
    t.ok(ranges)
    t.type(ranges, Array)
    t.equal(ranges.length, 2)

    const range1 = ranges[0]
    t.type(range1, RangeAttribute)
    t.equal(range1.attributeName, 'member')
    t.equal(range1.low, 0)
    t.equal(range1.high, 5)

    const range2 = ranges[1]
    t.type(range2, RangeAttribute)
    t.equal(range2.attributeName, 'foo')
    t.equal(range2.low, 100)
    t.equal(range2.high, 200)
    t.end()
  })

  t.test('should get the next range for an attribute', t => {
    const range = RangeAttribute.fromString('member;range=0-2')
    const range2 = range.next()
    t.ok(range2)
    t.equal(range2.attributeName, 'member')
    t.equal(range2.low, 3)
    t.equal(range2.high, 6)
    t.end()
  })

  t.test('should recognize the end of a range', t => {
    const range = RangeAttribute.fromString('member;range=5-*')
    t.ok(range)
    t.type(range, RangeAttribute)
    t.equal(range.low, 5)
    t.is(range.high, null)
    t.true(range.isComplete())
    t.end()
  })

  t.end()
})
