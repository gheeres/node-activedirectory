'use strict'
/* eslint-env node, mocha */
/* eslint-disable no-unused-expressions */

const expect = require('chai').expect
const path = require('path')
const RangeAttribute = require(path.join(__dirname, '..', 'lib', 'client', 'RangeAttribute'))

describe('Range Attribute Class', function () {
  it('should return determine if ranges are present', function (done) {
    let attrs = {}
    let hasRanges = RangeAttribute.hasRangeAttributes(attrs)
    expect(hasRanges).to.be.false

    attrs = {
      'member;range=0-5': {}
    }
    hasRanges = RangeAttribute.hasRangeAttributes(attrs)
    expect(hasRanges).to.be.true

    done()
  })

  it('should parse an attribute string with a range', function (done) {
    const attr = 'member;range=0-5'
    const rrsa = RangeAttribute(attr)
    expect(rrsa.attributeName).to.equal('member')
    expect(rrsa.low).to.equal(0)
    expect(rrsa.high).to.equal(5)
    done()
  })

  it('should parse multiple range attributes', function (done) {
    const attrs = {
      'member;range=0-5': {},
      'foo;range=100-200': {}
    }
    const ranges = RangeAttribute.getRangeAttributes(attrs)
    expect(ranges).to.not.be.null
    expect(ranges).to.be.an.instanceof(Array)
    expect(ranges.length).to.equal(2)

    const range1 = ranges[0]
    expect(range1).to.be.an.instanceof(RangeAttribute)
    expect(range1.attributeName).to.equal('member')
    expect(range1.low).to.equal(0)
    expect(range1.high).to.equal(5)

    const range2 = ranges[1]
    expect(range2).to.be.an.instanceof(RangeAttribute)
    expect(range2.attributeName).to.equal('foo')
    expect(range2.low).to.equal(100)
    expect(range2.high).to.equal(200)
    done()
  })

  it('should get the next range for an attribute', function (done) {
    const range = RangeAttribute.fromString('member;range=0-2')
    const range2 = range.next()
    expect(range2).to.not.be.null
    expect(range2.attributeName).to.equal('member')
    expect(range2.low).to.equal(3)
    expect(range2.high).to.equal(6)
    done()
  })

  it('should recognize the end of a range', function (done) {
    const range = RangeAttribute.fromString('member;range=5-*')
    expect(range).to.not.be.undefined
    expect(range).to.be.an.instanceof(RangeAttribute)
    expect(range.low).to.equal(5)
    expect(range.high).to.be.null
    expect(range.isComplete()).to.be.true
    done()
  })
})
