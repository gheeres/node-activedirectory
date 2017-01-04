'use strict'
/* eslint-env mocha, chai */

const expect = require('chai').expect
const ActiveDirectory = require('../index')
const config = require('./config')

let server = require('./mockServer')

describe('userExists Method', function () {
  let ad
  const settings = require('./settings').userExists

  before(function (done) {
    server(function (s) {
      ad = new ActiveDirectory(config)
      server = s
      done()
    })
  })

  it('should return true if the username (sAMAccountName) exists', function (done) {
    ad.userExists(settings.username.sAMAccountName, function (err, exists) {
      expect(err).to.be.null
      expect(exists).to.be.true
      done()
    })
  })

  it('should return true if the username (userPrincipalName) exists', function (done) {
    ad.userExists(settings.username.userPrincipalName, function (err, exists) {
      expect(err).to.be.null
      expect(exists).to.be.true
      done()
    })
  })

  it('should return true if the username (distinguishedName) exists', function (done) {
    ad.userExists(settings.username.sAMAccountName, function (err, exists) {
      expect(err).to.be.null
      expect(exists).to.be.true
      done()
    })
  })

  it('should return false if the username doesn\'t exist', function (done) {
    ad.userExists('!!!NON-EXISTENT USER!!!', function (err, exists) {
      expect(err).to.be.null
      expect(exists).to.be.false
      done()
    })
  })
})

