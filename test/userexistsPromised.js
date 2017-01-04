'use strict'
/* eslint-env mocha, chai */

const expect = require('chai').expect
const ActiveDirectory = require('../index').promiseWrapper
const config = require('./config')

let server = require('./mockServer')

describe('Promised userExists Method', function () {
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
    ad.userExists(settings.username.sAMAccountName)
      .then((exists) => {
        expect(exists).to.be.true
        done()
      })
      .catch(done)
  })

  it('should return true if the username (userPrincipalName) exists', function (done) {
    ad.userExists(settings.username.userPrincipalName)
      .then((exists) => {
        expect(exists).to.be.true
        done()
      })
      .catch(done)
  })

  it('should return true if the username (distinguishedName) exists', function (done) {
    ad.userExists(settings.username.sAMAccountName)
      .then((exists) => {
        expect(exists).to.be.true
        done()
      })
      .catch(done)
  })

  it('should return false if the username doesn\'t exist', function (done) {
    ad.userExists('!!!NON-EXISTENT USER!!!')
      .then((exists) => {
        expect(exists).to.be.false
        done()
      })
      .catch(done)
  })
})

