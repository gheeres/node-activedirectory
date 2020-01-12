'use strict'
/* eslint-env node, mocha */
/* eslint-disable no-unused-expressions */

const expect = require('chai').expect
const ActiveDirectory = require('../index')
const config = require('./config')

let server = require('./mockServer')

describe('Authentication', function () {
  let ad
  const settings = require('./settings').authenticate
  const LDAP_INVALID_CREDENTIALS = 49

  before(function (done) {
    server(function (s) {
      ad = new ActiveDirectory(config)
      server = s
      done()
    })
  })

  describe('#authenticate()', function () {
    it('should return true if the username (distinguishedName) and password are correct', function (done) {
      ad.authenticate(settings.username.dn, settings.password, function (err, auth) {
        expect(err).to.be.null
        expect(auth).to.be.true
        done()
      })
    })

    it('should return true if the username (userPrincipalName) and password are correct', function (done) {
      ad.authenticate(settings.username.userPrincipalName, settings.password, function (err, auth) {
        expect(err).to.be.null
        expect(auth).to.be.true
        done()
      })
    })

    it('should return true if the username (DOMAIN\\username) and password are correct', function (done) {
      ad.authenticate(settings.username.domainUsername, settings.password, function (err, auth) {
        expect(err).to.be.null
        expect(auth).to.be.true
        done()
      })
    })

    it('should return empty or null err if the username and password are correct', function (done) {
      ad.authenticate(settings.username.domainUsername, settings.password, function (err, auth) {
        expect(err).to.be.null
        expect(auth).to.be.true
        done()
      })
    })

    it('should return false if username is null', function (done) {
      ad.authenticate(null, settings.password, function (err, auth) {
        expect(err).to.be.an('object')
        expect(err.code).to.exist
        expect(err.code).to.equal(LDAP_INVALID_CREDENTIALS)
        expect(auth).to.be.false
        done()
      })
    })

    it('should return false if username is an empty string.', function (done) {
      ad.authenticate('', settings.password, function (err, auth) {
        expect(err).to.be.an('object')
        expect(err.code).to.exist
        expect(err.code).to.equal(LDAP_INVALID_CREDENTIALS)
        expect(auth).to.be.false
        done()
      })
    })

    it('should return err with LDAP_INVALID_CREDENTIALS if username and password are incorrect', function (done) {
      ad.authenticate('CN=invalid,DC=domain,DC=com', '!!!INVALID PASSWORD!!!', function (err, auth) {
        expect(err).to.be.an('object')
        expect(err.code).to.exist
        expect(err.code).to.equal(LDAP_INVALID_CREDENTIALS)
        expect(auth).to.be.false
        done()
      })
    })
  })
})
