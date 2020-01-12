'use strict'
/* eslint-env node, mocha */
/* eslint-disable no-unused-expressions */

const expect = require('chai').expect
const ActiveDirectory = require('../index')
const config = require('./config')

let server = require('./mockServer')

describe('Attributes', function () {
  let ad
  const settings = require('./settings').findUser

  const defaultAttributes = ActiveDirectory.defaultAttributes.user

  before(function (done) {
    server(function (s) {
      server = s
      done()
    })
  })

  function validateAllAttrs (err, user, done) {
    expect(err).to.be.null
    expect(user).to.be.an('object')

    const attributes = Object.keys(user)
    expect(attributes.length).to.be.greaterThan(defaultAttributes.length)
    done()
  }

  it('should return default user attributes when not specified', function (done) {
    ad = new ActiveDirectory(config)
    ad.findUser(settings.username.userPrincipalName, function (err, user) {
      expect(err).to.be.null
      expect(user).to.be.an('object')

      const attributes = Object.keys(user)
      expect(attributes.length).be.at.least(defaultAttributes.length)

      for (let attr of attributes) {
        expect(defaultAttributes).to.include(attr)
      }
      done()
    })
  })

  it('when default attributes contains a wildcard, should return all attributes', function (done) {
    const localConfig = Object.assign({}, config, {
      attributes: {
        user: [ '*' ]
      }
    })
    ad = new ActiveDirectory(localConfig)
    ad.findUser(settings.username.userPrincipalName, function (err, user) {
      validateAllAttrs(err, user, done)
    })
  })

  it('when default attributes is empty array, should return all attributes', function (done) {
    const localConfig = Object.assign({}, config, {
      attributes: {
        user: [ ]
      }
    })
    ad = new ActiveDirectory(localConfig)
    ad.findUser(settings.username.userPrincipalName, function (err, user) {
      validateAllAttrs(err, user, done)
    })
  })

  it('when opts.attributes contains a wildcard, should return all attributes', function (done) {
    const opts = {
      attributes: [ '*' ]
    }
    ad = new ActiveDirectory(config)
    ad.findUser(opts, settings.username.userPrincipalName, function (err, user) {
      validateAllAttrs(err, user, done)
    })
  })

  it('when opts.attributes is empty array, should return all attributes', function (done) {
    const opts = {
      attributes: [ ]
    }
    ad = new ActiveDirectory(config)
    ad.findUser(opts, settings.username.userPrincipalName, function (err, user) {
      validateAllAttrs(err, user, done)
    })
  })
})
