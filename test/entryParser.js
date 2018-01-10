'use strict'
/* eslint-env node, mocha */
/* eslint-disable no-unused-expressions */

const expect = require('chai').expect
const ActiveDirectory = require('../index')
const config = require('./config')

let server = require('./mockServer')

describe('entryParser', function () {
  let ad
  const settings = require('./settings').findUser

  before(function (done) {
    server(function (s) {
      server = s
      done()
    })
  })

  it('should return objectSid as human readable string from default entryParser', function (done) {
    ad = new ActiveDirectory(config)
    const opts = {
      attributes: ['objectSid']
    }
    ad.findUser(opts, settings.username.userPrincipalName, function (err, user) {
      expect(err).to.be.null
      expect(user.objectSid).to.not.be.undefined
      expect(user.objectSid).to.be.string
      done()
    })
  })

  it('should return custom attribute set by custom entryParser in global config', function (done) {
    config.entryParser = function (entry, raw, cb) {
      entry.foobar = true
      cb(entry)
    }
    ad = new ActiveDirectory(config)
    const opts = {
      attributes: ['foobar']
    }
    ad.findUser(opts, settings.username.userPrincipalName, function (err, user) {
      expect(err).to.be.null
      expect(user.foobar).to.be.true
      done()
    })
  })

  it('should return custom attribute set by custom entryParser in local config', function (done) {
    ad = new ActiveDirectory(config)
    const opts = {
      attributes: ['foobar'],
      entryParser: function (entry, raw, cb) {
        entry.foobar = true
        cb(entry)
      }
    }
    ad.findUser(opts, settings.username.userPrincipalName, function (err, user) {
      expect(err).to.be.null
      expect(user.foobar).to.be.true
      done()
    })
  })
})
