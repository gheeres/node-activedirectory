'use strict'

const tap = require('tap')
const ActiveDirectory = require('../index')
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
  t.context.ad.groupExists(settings.sAMAccountName, settings.groupName.cn, function (err, exists) {
    t.error(err)
    t.true(exists)
    t.end()
  })
})

tap.test('should return true if the groupName (distinguishedName) exists', t => {
  t.context.ad.groupExists(settings.sAMAccountName, settings.groupName.dn, function (err, exists) {
    t.error(err)
    t.true(exists)
    t.end()
  })
})

tap.test('should return false if the groupName doesn\'t exist', t => {
  t.context.ad.groupExists(settings.sAMAccountName, '!!!NON-EXISTENT GROUP!!!', function (err, exists) {
    t.error(err)
    t.false(exists)
    t.end()
  })
})
