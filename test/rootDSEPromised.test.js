'use strict'

const tap = require('tap')
const ActiveDirectory = require('../index').promiseWrapper
const config = require('./config')
const serverFactory = require('./mockServer')

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
  t.context.server = undefined
  t.context.ad = undefined
  done()
})

tap.test('should return ECONNREFUSED for closed port', t => {
  return ActiveDirectory.getRootDSE('ldap://127.0.0.1:389')
    .then(() => t.fail('should not be invoked'))
    .catch((err) => {
      t.ok(err)
      t.type(err, Error)
      t.equal(err.errno, 'ECONNREFUSED')
    })
})

tap.test('should return an error if no url specified', t => {
  return ActiveDirectory.getRootDSE(null)
    .then(() => t.fail('should not be invoked'))
    .catch((err) => {
      t.ok(err)
      t.type(err, Error)
      t.match(err.message, /in the form/)
    })
})

// TODO: remainder of the tests are skipped because the client internal to
// getRootDSE method is not receiving an "end" event. This causes the client
// socket to stay open and in turn the tests to timeout. I suspect this is an
// upstream error in ldapjs.
tap.skip('should use the instance url property if omitted', t => {
  return t.context.ad.getRootDSE()
    .then((result) => t.ok(result))
    .catch(t.error)
})

tap.skip('should return all attributes when none specified', t => {
  const attrs = ['dn', 'dnsHostName', 'serverName', 'supportedLDAPVersion']
  const port = t.context.server.port
  return t.context.ad.getRootDSE(`ldap://127.0.0.1:${port}`)
    .then((result) => {
      t.ok(result)
      const keys = Object.keys(result)
      keys.forEach((k) => t.true(attrs.includes(k)))
    })
    .catch(t.error)
})

tap.skip('should return only specified attributes', t => {
  // dn is always returned
  const attrs = ['dn', 'supportedLDAPVersion']
  const port = t.context.server.port
  return t.context.ad.getRootDSE(`ldap://127.0.0.1:${port}`, attrs)
    .then((result) => {
      t.ok(result)
      const keys = Object.keys(result)
      keys.forEach((k) => t.true(attrs.includes(k)))
    })
    .catch(t.error)
})

tap.skip('should not return the controls attribute', t => {
  const port = t.context.server.port
  return t.context.ad.getRootDSE(`ldap://127.0.0.1:${port}`)
    .then((result) => {
      t.ok(result)
      const keys = Object.keys(result)
      t.equal(keys.indexOf('controls'), -1)
    })
    .catch(t.error)
})
