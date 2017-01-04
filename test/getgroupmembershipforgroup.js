'use strict'
/* eslint-env mocha, chai */

const expect = require('chai').expect
const ActiveDirectory = require('../index')
const config = require('./config')

let server = require('./mockServer')

describe('getGroupMembershipForGroup Method', function () {
  let ad
  const settings = require('./settings').getGroupMembershipForGroup

  before(function (done) {
    server(function (s) {
      ad = new ActiveDirectory(config)
      server = s
      done()
    })
  })

  describe('#getGroupMembershipForGroup()', function () {
    settings.groups.forEach((group) => {
      ['dn', 'cn'].forEach((groupAttribute) => {
        const len = group.members.length
        const expectedGroup = group[groupAttribute]
        it(`should return ${len} groups for (${groupAttribute}) ${expectedGroup}`, function (done) {
          ad.getGroupMembershipForGroup(expectedGroup, function (err, groups) {
            expect(err).to.be.null
            expect(groups).to.not.be.undefined
            expect(Array.isArray(groups)).to.be.true

            const cns = groups.map((g) => g.cn)
            expect(cns).to.deep.include.members(group.members)

            done()
          })
        })
      })
    })

    it('should return empty groups if groupName doesn\'t exist', function (done) {
      ad.getGroupMembershipForGroup('!!!NON-EXISTENT GROUP!!!', function (err, groups) {
        expect(err).to.be.undefined
        expect(groups).to.be.undefined
        done()
      })
    })

    it('should return default group attributes when not specified', function (done) {
      const defaultAttributes = ActiveDirectory.defaultAttributes.group
      const group = settings.groups[0]
      ad.getGroupMembershipForGroup(group.dn, function (err, groups) {
        expect(err).to.be.null
        expect(groups).to.not.be.undefined
        expect(Array.isArray(groups)).to.be.true

        groups.forEach((group) => {
          const keys = Object.keys(group)
          expect(keys.length).to.equal(defaultAttributes.length)
        })

        done()
      })
    })
  })

  describe('#getGroupMembershipForGroup(opts)', function () {
    it('should return only requested attributes', function (done) {
      const opts = {
        attributes: [ 'createTimeStamp' ]
      }
      const group = settings.groups[0]
      ad.getGroupMembershipForGroup(opts, group.dn, function (err, groups) {
        expect(err).to.be.null
        expect(groups).to.not.be.undefined
        expect(Array.isArray(groups)).to.be.true
        expect(groups.length).to.be.gte(group.members.length)

        groups.forEach((group) => {
          const keys = Object.keys(group)
          expect(keys.length).to.equal(opts.attributes.length)
          expect(keys).to.deep.include.members(opts.attributes)
        })

        done()
      })
    })
  })
})

