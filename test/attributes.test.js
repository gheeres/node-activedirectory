'use strict'

const tap = require('tap')
const ActiveDirectory = require('../index')
const config = require('./config')
const serverFactory = require('./mockServer')

tap.test('Attributes', t => {
  const settings = require('./settings').findUser
  const defaultAttributes = ActiveDirectory.defaultAttributes.user

  t.beforeEach((done, t) => {
    serverFactory(function (err, server) {
      if (err) return done(err)
      t.context.ad = null
      t.context.server = server
      done()
    })
  })

  t.afterEach((done, t) => {
    if (t.context.server) t.context.server.close()
    done()
  })

  function validateAllAttrs (t, err, user, done) {
    t.error(err)
    t.type(user, 'object')

    const attributes = Object.keys(user)
    t.true(attributes.length > defaultAttributes.length)
    done()
  }

  t.test('should return default user attributes when not specified', t => {
    const connectionConfig = config(t.context.server.port)
    t.context.ad = new ActiveDirectory(connectionConfig)
    t.context.ad.findUser(settings.username.userPrincipalName, function (err, user) {
      t.error(err)
      t.type(user, 'object')

      const attributes = Object.keys(user)
      t.true(attributes.length >= defaultAttributes.length)

      for (const attr of attributes) {
        t.true(defaultAttributes.includes(attr))
      }

      t.end()
    })
  })

  t.test('when default attributes contains a wildcard, should return all attributes', t => {
    const connectionConfig = config(t.context.server.port)
    const localConfig = Object.assign({}, connectionConfig, {
      attributes: {
        user: ['*']
      }
    })
    t.context.ad = new ActiveDirectory(localConfig)
    t.context.ad.findUser(settings.username.userPrincipalName, function (err, user) {
      validateAllAttrs(t, err, user, t.end)
    })
  })

  t.test('when default attributes is empty array, should return all attributes', t => {
    const connectionConfig = config(t.context.server.port)
    const localConfig = Object.assign({}, connectionConfig, {
      attributes: {
        user: []
      }
    })
    t.context.ad = new ActiveDirectory(localConfig)
    t.context.ad.findUser(settings.username.userPrincipalName, function (err, user) {
      validateAllAttrs(t, err, user, t.end)
    })
  })

  t.test('when opts.attributes contains a wildcard, should return all attributes', t => {
    const opts = {
      attributes: ['*']
    }
    const connectionConfig = config(t.context.server.port)
    t.context.ad = new ActiveDirectory(connectionConfig)
    t.context.ad.findUser(opts, settings.username.userPrincipalName, function (err, user) {
      validateAllAttrs(t, err, user, t.end)
    })
  })

  t.test('when opts.attributes is empty array, should return all attributes', t => {
    const opts = {
      attributes: []
    }
    const connectionConfig = config(t.context.server.port)
    t.context.ad = new ActiveDirectory(connectionConfig)
    t.context.ad.findUser(opts, settings.username.userPrincipalName, function (err, user) {
      validateAllAttrs(t, err, user, t.end)
    })
  })

  t.end()
})
