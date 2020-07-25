'use strict'

const tap = require('tap')
const ActiveDirectory = require('../index').promiseWrapper
const config = require('./config')
const serverFactory = require('./mockServer')
const settings = require('./settings').groupExists

tap.beforeEach((done, t) => {
  serverFactory(function (err, server) {
    if (err) return done(err)
    const connectionConfig = config(server.port)
    t.context.ad = new ActiveDirectory(connectionConfig)
    t.context.server = server
    done()
  })
})

tap.afterEach((done, t) => {
  if (t.context.server) t.context.server.close()
  done()
})

tap.test('should return true if the groupName (commonName) exists', t => {
  return t.context.ad.groupExists(settings.sAMAccountName, settings.groupName.cn)
    .then((exists) => {
      t.true(exists)
    })
    .catch(t.error)
})

tap.test('should return true if the groupName (distinguishedName) exists', t => {
  return t.context.ad.groupExists(settings.sAMAccountName, settings.groupName.dn)
    .then((exists) => {
      t.true(exists)
    })
    .catch(t.error)
})

tap.test('should return false if the groupName doesn\'t exist', t => {
  return t.context.ad.groupExists(settings.sAMAccountName, '!!!NON-EXISTENT GROUP!!!')
    .then((exists) => {
      t.false(exists)
    })
    .catch(t.error)
})
