'use strict'

const tap = require('tap')
const ActiveDirectory = require('../index').promiseWrapper
const config = require('./config')
const serverFactory = require('./mockServer')

tap.test('#authenticate', t => {
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
    return t.context.ad.authenticate(settings.username.dn, settings.password)
      .then((auth) => t.true(auth))
      .catch(t.error)
  })

  t.test('should return true if the username (userPrincipalName) and password are correct', t => {
    return t.context.ad.authenticate(settings.username.userPrincipalName, settings.password)
      .then((auth) => t.true(auth))
      .catch(t.error)
  })

  t.test('should return true if the username (DOMAIN\\username) and password are correct', t => {
    return t.context.ad.authenticate(settings.username.domainUsername, settings.password)
      .then((auth) => t.true(auth))
      .catch(t.error)
  })

  t.test('should return empty or null err if the username and password are correct', t => {
    return t.context.ad.authenticate(settings.username.domainUsername, settings.password)
      .then((auth) => t.true(auth))
      .catch(t.error)
  })

  t.test('should return false if username is null', t => {
    return t.context.ad.authenticate(null, settings.password)
      .then(() => t.fail('should not be invoked'))
      .catch((err) => {
        t.type(err, 'object')
        t.match(err, { code: LDAP_INVALID_CREDENTIALS })
      })
  })

  t.test('should return false if username is an empty string.', t => {
    return t.context.ad.authenticate('', settings.password)
      .then(() => t.fail('should not be invoked'))
      .catch((err) => {
        t.type(err, 'object')
        t.match(err, { code: LDAP_INVALID_CREDENTIALS })
      })
  })

  t.test('should return err with LDAP_INVALID_CREDENTIALS if username and password are incorrect', t => {
    return t.context.ad.authenticate('CN=invalid,DC=domain,DC=com', '!!!INVALID PASSWORD!!!')
      .then(() => t.fail('should not be invoked'))
      .catch((err) => {
        t.type(err, 'object')
        t.match(err, { code: LDAP_INVALID_CREDENTIALS })
      })
  })

  t.end()
})
