'use strict'

const tap = require('tap')
const ActiveDirectory = require('../index')
const config = require('./config')
const serverFactory = require('./mockServer')

tap.test('#authenticate()', t => {
  const settings = require('./settings').authenticate
  const LDAP_INVALID_CREDENTIALS = 49

  t.beforeEach((done, t) => {
    serverFactory(function (err, server) {
      if (err) return done(err)
      const connectionConfig = config(server.port)
      t.context.ad = new ActiveDirectory(connectionConfig)
      t.context.server = server
      done()
    })
  })

  t.afterEach((done, t) => {
    if (t.context.server) t.context.server.close()
    done()
  })

  t.test('should return true if the username (distinguishedName) and password are correct', t => {
    t.context.ad.authenticate(settings.username.dn, settings.password, function (err, auth) {
      t.error(err)
      t.true(auth)
      t.end()
    })
  })

  t.test('should return true if the username (userPrincipalName) and password are correct', t => {
    t.context.ad.authenticate(settings.username.userPrincipalName, settings.password, function (err, auth) {
      t.error(err)
      t.true(auth)
      t.end()
    })
  })

  t.test('should return true if the username (DOMAIN\\username) and password are correct', t => {
    t.context.ad.authenticate(settings.username.domainUsername, settings.password, function (err, auth) {
      t.error(err)
      t.true(auth)
      t.end()
    })
  })

  t.test('should return empty or null err if the username and password are correct', t => {
    t.context.ad.authenticate(settings.username.domainUsername, settings.password, function (err, auth) {
      t.error(err)
      t.true(auth)
      t.end()
    })
  })

  t.test('should return false if username is null', t => {
    t.context.ad.authenticate(null, settings.password, function (err, auth) {
      t.type(err, 'object')
      t.match(err, {
        code: LDAP_INVALID_CREDENTIALS
      })
      t.false(auth)
      t.end()
    })
  })

  t.test('should return false if username is an empty string.', t => {
    t.context.ad.authenticate('', settings.password, function (err, auth) {
      t.type(err, 'object')
      t.match(err, {
        code: LDAP_INVALID_CREDENTIALS
      })
      t.false(auth)
      t.end()
    })
  })

  t.test('should return err with LDAP_INVALID_CREDENTIALS if username and password are incorrect', t => {
    t.context.ad.authenticate('CN=invalid,DC=domain,DC=com', '!!!INVALID PASSWORD!!!', function (err, auth) {
      t.type(err, 'object')
      t.match(err, {
        code: LDAP_INVALID_CREDENTIALS
      })
      t.false(auth)
      t.end()
    })
  })

  t.end()
})
