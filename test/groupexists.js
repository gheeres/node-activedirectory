'use strict'
/* eslint-env node, mocha */
/* eslint-disable no-unused-expressions */

const expect = require('chai').expect
const ActiveDirectory = require('../index')
const config = require('./config')

let server = require('./mockServer')

describe('groupExists Method', function () {
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
    ad.groupExists(settings.sAMAccountName, settings.groupName.cn, function (err, exists) {
      expect(err).to.be.null
      expect(exists).to.be.true
      done()
    })
  })

  it('should return true if the groupName (distinguishedName) exists', function (done) {
    ad.groupExists(settings.sAMAccountName, settings.groupName.dn, function (err, exists) {
      expect(err).to.be.null
      expect(exists).to.be.true
      done()
    })
  })

  it('should return false if the groupName doesn\'t exist', function (done) {
    ad.groupExists(settings.sAMAccountName, '!!!NON-EXISTENT GROUP!!!', function (err, exists) {
      expect(err).to.be.null
      expect(exists).to.be.false
      done()
    })
  })
})
