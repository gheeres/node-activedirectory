'use strict'
/* eslint-env node, mocha */
/* eslint-disable no-unused-expressions */

const expect = require('chai').expect
const ActiveDirectory = require('../index').promiseWrapper
const config = require('./config')

let server = require('./mockServer')

describe('Promised findGroups Method', function () {
  let ad
  const settings = require('./settings').findGroups
  const timeout = 6000 // The timeout in milliseconds before a test is considered failed.

  before(function (done) {
    server(function (s) {
      ad = new ActiveDirectory(config)
      server = s
      done()
    })
  })

  describe('#findGroups()', function () {
    settings.groups.forEach((group) => {
      const len = group.results.length
      const query = (group.query.filter) ? group.query.filter : group.query
      it(`should return ${len} groups for query '${query}'`, function (done) {
        this.timeout(timeout)

        const expectedResults = group.results
        ad.findGroups(query)
          .then((groups) => {
            expect(groups).to.not.be.null
            expect(Array.isArray(groups)).to.be.true
            expect(groups.length).to.equal(len)

            const cns = groups.map((g) => g.cn)
            expect(cns).to.be.any.members(expectedResults)
            done()
          })
          .catch(done)
      })
    })

    it('should return default group attributes when not specified', function (done) {
      const defaultAttributes = ad.defaultAttributes.group
      const group = settings.groups[0]
      ad.findGroups(group.query)
        .then((groups) => {
          expect(groups).to.not.be.null
          expect(Array.isArray(groups)).to.be.true

          groups.forEach((group) => {
            const attributes = Object.keys(group)
            expect(attributes.length).to.be.lte(defaultAttributes.length)
            expect(attributes).to.be.any.members(defaultAttributes)
          })

          done()
        })
        .catch(done)
    })
  })

  describe('#findGroups(opts)', function () {
    it('should include groups/membership if opts.includeMembership[] = [ \'all\' ]', function (done) {
      this.timeout(timeout)

      const group = settings.groups[0]
      const opts = {
        includeMembership: [ 'all' ],
        filter: group.query
      }
      ad.findGroups(opts)
        .then((groups) => {
          expect(groups).to.not.be.null
          expect(Array.isArray(groups)).to.be.true

          groups.forEach((group) => {
            expect(group.groups).to.exist
          })

          done()
        })
        .catch(done)
    })

    it('should include groups/membership if opts.includeMembership[] = [ \'group\' ]', function (done) {
      this.timeout(timeout)

      const group = settings.groups[0]
      const opts = {
        includeMembership: [ 'group' ],
        filter: group.query
      }
      ad.findGroups(opts)
        .then((groups) => {
          expect(groups).to.not.be.null
          expect(Array.isArray(groups)).to.be.true

          groups.forEach((group) => {
            expect(group.groups).to.exist
          })

          done()
        })
        .catch(done)
    })
    it('should not include groups/membership if opts.includeMembership disabled', function (done) {
      var group = settings.groups[0]
      var opts = {
        includeMembership: false,
        filter: group.query
      }
      ad.findGroups(opts)
        .then((groups) => {
          expect(groups).to.not.be.null
          expect(Array.isArray(groups)).to.be.true

          groups.forEach((group) => {
            expect(group.groups).to.not.exist
          })

          done()
        })
        .catch(done)
    })

    it('should return only requested attributes', function (done) {
      const group = settings.groups[0]
      const opts = {
        attributes: [ 'cn' ],
        filter: group.query
      }
      ad.findGroups(opts)
        .then((groups) => {
          expect(groups).to.not.be.null
          expect(Array.isArray(groups)).to.be.true

          groups.forEach((group) => {
            const keys = Object.keys(group)
            expect(keys.length).to.equal(opts.attributes.length)
            expect(keys).to.be.any.members(opts.attributes)
          })

          done()
        })
        .catch(done)
    })
  })
})
