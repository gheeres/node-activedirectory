'use strict'
/* eslint-env mocha, chai */

const expect = require('chai').expect
const ActiveDirectory = require('../index').promiseWrapper
const config = require('./config')

let server = require('./mockServer')

describe('Promised groupExists Method', function () {
  let ad
  const settings = require('./settings').groupExists

  before(function (done) {
    server(function (s) {
      ad = new ActiveDirectory(config)
      server = s
      done()
    })
  })

  it('should return true if the groupName (commonName) exists', function (done) {
    ad.groupExists(settings.sAMAccountName, settings.groupName.cn)
      .then((exists) => {
        expect(exists).to.be.true
        done()
      })
      .catch(done)
  })

  it('should return true if the groupName (distinguishedName) exists', function (done) {
    ad.groupExists(settings.sAMAccountName, settings.groupName.dn)
      .then((exists) => {
        expect(exists).to.be.true
        done()
      })
      .catch(done)
  })

  it('should return false if the groupName doesn\'t exist', function (done) {
    ad.groupExists(settings.sAMAccountName, '!!!NON-EXISTENT GROUP!!!')
      .then((exists) => {
        expect(exists).to.be.false
        done()
      })
      .catch(done)
  })
})

