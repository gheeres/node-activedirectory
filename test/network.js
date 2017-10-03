'use strict'
/* eslint-env node, mocha */
/* eslint-disable no-unused-expressions */

const expect = require('chai').expect
const ldapjs = require('ldapjs')
const ActiveDirectory = require('../index')

describe('Network Connections', function () {
  const username = 'username'
  const password = 'password'

  describe('#authenticate()', function () {
    it('should return err (ENOTFOUND) on invalid hostname (dns)', function (done) {
      const ad = new ActiveDirectory({
        url: 'ldap://invalid.domain.net'
      })
      ad.authenticate(username, password, function (err, auth) {
        expect(err).to.be.an.instanceof(Error)
        expect(err.code).to.equal('ENOTFOUND')
        expect(auth).to.be.false
        done()
      })
    })

    it('should return err (ECONNREFUSED) on non listening port', function (done) {
      const ad = new ActiveDirectory({
        url: 'ldap://127.0.0.1:65535/'
      })
      ad.authenticate(username, password, function (err, auth) {
        expect(err).to.be.an.instanceof(Error)
        expect(err.code).to.equal('ECONNREFUSED')
        expect(auth).to.be.false
        done()
      })
    })

    it('should return err (ConnectionError) when connection timeouts', function (done) {
      const ad = new ActiveDirectory({
        url: 'ldap://example.com',
        connectTimeout: 1
      })
      ad.authenticate(username, password, function (err, auth) {
        expect(err).to.be.an.instanceOf(ldapjs.ConnectionError)
        expect(auth).to.be.false
        done()
      })
    })
  })
})
