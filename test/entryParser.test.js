'use strict'

const tap = require('tap')
const ActiveDirectory = require('../index')
const config = require('./config')
const serverFactory = require('./mockServer')

tap.test('entryParser', t => {
  const settings = require('./settings').findUser

  t.beforeEach((done, t) => {
    serverFactory(function (err, server) {
      if (err) return done(err)
      t.context.ad = null
      t.context.server = server
      done()
    })
  })

  t.afterEach((done, t) => {
    if (t.context.server) {
      t.context.server.close()
    }
    done()
  })

  t.test('should return objectSid as human readable string from default entryParser', t => {
    const localConfig = config(t.context.server.port)
    t.context.ad = new ActiveDirectory(localConfig)
    const opts = {
      attributes: ['objectSid']
    }
    t.context.ad.findUser(opts, settings.username.userPrincipalName, function (err, user) {
      t.error(err)
      t.type(user.objectSid, 'string')
      t.end()
    })
  })

  t.test('should return custom attribute set by custom entryParser in global config', t => {
    const localConfig = config(t.context.server.port)
    localConfig.entryParser = function (entry, raw, cb) {
      entry.foobar = true
      cb(entry)
    }
    t.context.ad = new ActiveDirectory(localConfig)
    const opts = {
      attributes: ['foobar']
    }
    t.context.ad.findUser(opts, settings.username.userPrincipalName, function (err, user) {
      t.error(err)
      t.true(user.foobar)
      t.end()
    })
  })

  t.test('should return custom attribute set by custom entryParser in local config', t => {
    const localConfig = config(t.context.server.port)
    t.context.ad = new ActiveDirectory(localConfig)
    const opts = {
      attributes: ['foobar'],
      entryParser: function (entry, raw, cb) {
        entry.foobar = true
        cb(entry)
      }
    }
    t.context.ad.findUser(opts, settings.username.userPrincipalName, function (err, user) {
      t.error(err)
      t.true(user.foobar)
      t.end()
    })
  })

  t.end()
})
