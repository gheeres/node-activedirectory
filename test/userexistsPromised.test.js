'use strict'

const tap = require('tap')
const ActiveDirectory = require('../index').promiseWrapper
const config = require('./config')
const serverFactory = require('./mockServer')
const settings = require('./settings').userExists

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

tap.test('should return true if the username (sAMAccountName) exists', t => {
  return t.context.ad.userExists(settings.username.sAMAccountName)
    .then((exists) => t.true(exists))
    .catch(t.error)
})

tap.test('should return true if the username (userPrincipalName) exists', t => {
  return t.context.ad.userExists(settings.username.userPrincipalName)
    .then((exists) => t.true(exists))
    .catch(t.error)
})

tap.test('should return true if the username (distinguishedName) exists', t => {
  return t.context.ad.userExists(settings.username.sAMAccountName)
    .then((exists) => t.true(exists))
    .catch(t.error)
})

tap.test('should return false if the username doesn\'t exist', t => {
  return t.context.ad.userExists('!!!NON-EXISTENT USER!!!')
    .then((exists) => t.false(exists))
    .catch(t.error)
})
