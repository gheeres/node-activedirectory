'use strict'
/* eslint-env node, mocha */
/* eslint-disable no-unused-expressions */

const expect = require('chai').expect
const ActiveDirectory = require('../index').promiseWrapper
const config = require('./config')

let server = require('./mockServer')

describe('Promised getGroupMembershipForGroup Method', function () {
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
          ad.getGroupMembershipForGroup(expectedGroup)
            .then((groups) => {
              expect(groups).to.not.be.undefined
              expect(Array.isArray(groups)).to.be.true

              const cns = groups.map((g) => g.cn)
              expect(cns).to.deep.include.members(group.members)

              done()
            })
            .catch(done)
        })
      })
    })

    it('should return empty groups if groupName doesn\'t exist', function (done) {
      ad.getGroupMembershipForGroup('!!!NON-EXISTENT GROUP!!!')
        .then((groups) => {
          expect(groups).to.be.undefined
          done()
        })
        .catch(done)
    })

    it('should return default group attributes when not specified', function (done) {
      const defaultAttributes = ad.defaultAttributes.group
      const group = settings.groups[0]
      ad.getGroupMembershipForGroup(group.dn)
        .then((groups) => {
          expect(groups).to.not.be.undefined
          expect(Array.isArray(groups)).to.be.true

          groups.forEach((group) => {
            const keys = Object.keys(group)
            expect(keys.length).to.equal(defaultAttributes.length)
          })

          done()
        })
        .catch(done)
    })
  })

  describe('#getGroupMembershipForGroup(opts)', function () {
    it('should return only requested attributes', function (done) {
      const opts = {
        attributes: [ 'createTimeStamp' ]
      }
      const group = settings.groups[0]
      ad.getGroupMembershipForGroup(opts, group.dn)
        .then((groups) => {
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
        .catch(done)
    })
  })
})
