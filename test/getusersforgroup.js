'use strict'
/* eslint-env node, mocha */
/* eslint-disable no-unused-expressions */

const expect = require('chai').expect
const ActiveDirectory = require('../index')
const config = require('./config')

let server = require('./mockServer')

describe('getUsersForGroup method', function () {
  let ad
  const settings = require('./settings').getUsersForGroup

  before(function (done) {
    server(function (s) {
      ad = new ActiveDirectory(config)
      server = s
      done()
    })
  })

  describe('#getUsersForGroup()', function () {
    settings.groups.forEach((group) => {
      const len = group.users.length
      it(`should return ${len} users for (distinguishedName) ${group.dn}`, function (done) {
        ad.getUsersForGroup(group.dn, function (err, users) {
          expect(err).to.be.null
          expect(users).to.not.be.null
          expect(users.length).to.equal(len)

          const dns = users.map((u) => {
            return u.dn.toLowerCase().replace(/[\s\\]/g, '')
          })
          group.users.forEach((source) => {
            const testStr = source.toLowerCase().replace(/\s/g, '')
            expect(dns).to.contain(testStr)
          })

          done()
        })
      })

      it(`should return ${len} users for (commonName) ${group.cn}`, function (done) {
        ad.getUsersForGroup(group.cn, function (err, users) {
          expect(err).to.be.null
          expect(users).to.not.be.null
          expect(users.length).to.equal(len)

          const dns = users.map((u) => {
            return u.dn.toLowerCase().replace(/[\s\\]/g, '')
          })
          group.users.forEach((source) => {
            const testStr = source.toLowerCase().replace(/\s/g, '')
            expect(dns).to.contain(testStr)
          })

          done()
        })
      })
    })

    it('should return empty users if groupName doesn\'t exist', function (done) {
      ad.getUsersForGroup('!!!NON-EXISTENT GROUP!!!', function (err, users) {
        expect(err).to.be.null
        expect(users).to.be.undefined
        done()
      })
    })

    it('should return default user attributes when not specified', function (done) {
      const defaultAttributes = [
        'dn', 'distinguishedName',
        'userPrincipalName', 'sAMAccountName', /* 'objectSID', */ 'mail',
        'lockoutTime', 'whenCreated', 'pwdLastSet', 'userAccountControl',
        'employeeID', 'sn', 'givenName', 'initials', 'cn', 'displayName',
        'comment', 'description'
      ]
      const group = settings.groups[0]
      ad.getUsersForGroup(group.dn, function (err, users) {
        expect(err).to.be.null
        expect(users).to.not.be.undefined
        users.forEach((u) => {
          expect(Object.keys(u).length).to.equal(defaultAttributes.length)
        })
        done()
      })
    })
  })

  describe('#getUsersForGroup(opts)', function () {
    it('should return only requested attributes', function (done) {
      const opts = {
        attributes: [ 'createTimeStamp' ]
      }
      const group = settings.groups[0]
      ad.getUsersForGroup(opts, group.dn, function (err, users) {
        expect(err).to.be.null
        expect(users).to.not.be.undefined
        expect(users.length).to.equal(group.users.length)

        users.forEach((u) => {
          const keys = Object.keys(u)
          expect(keys.length).to.equal(opts.attributes.length)
          keys.forEach((k) => {
            expect(opts.attributes).to.contain(k)
          })
        })

        done()
      })
    })
  })
})
