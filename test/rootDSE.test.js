'use strict'

const tap = require('tap')
const ActiveDirectory = require('../index')
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
  ActiveDirectory.getRootDSE('ldap://127.0.0.1:389', (err) => {
    t.ok(err)
    t.type(err, Error)
    t.equal(err.errno, 'ECONNREFUSED')
    t.end()
  })
})

tap.test('should return an error if no url specified', t => {
  t.throws(
    ActiveDirectory.getRootDSE.bind(null, null, () => {})
  )
  t.end()
})

// TODO: remainder of the tests are skipped because the client internal to
// getRootDSE method is not receiving an "end" event. This causes the client
// socket to stay open and in turn the tests to timeout. I suspect this is an
// upstream error in ldapjs.
tap.skip('should use the instance url property if omitted', t => {
  t.context.ad.getRootDSE((err, result) => {
    t.error(err)
    t.ok(result)
    setImmediate(() => t.end())
  })
})

tap.skip('should return all attributes when none specified', t => {
  const attrs = ['dn', 'dnsHostName', 'serverName', 'supportedLDAPVersion']
  const port = t.context.server.port
  t.context.ad.getRootDSE(`ldap://127.0.0.1:${port}`, (err, result) => {
    t.error(err)
    t.ok(result)
    const keys = Object.keys(result)
    keys.forEach((k) => t.true(attrs.includes(k)))
    t.end()
  })
})

tap.skip('should return only specified attributes', t => {
  // dn is always returned
  const attrs = ['dn', 'supportedLDAPVersion']
  const port = t.context.server.port
  t.context.ad.getRootDSE(`ldap://127.0.0.1:${port}`, attrs, (err, result) => {
    t.error(err)
    t.ok(result)
    const keys = Object.keys(result)
    keys.forEach((k) => t.true(attrs.includes(k)))
    t.end()
  })
})

tap.skip('should not return the controls attribute', t => {
  const port = t.context.server.port
  t.context.ad.getRootDSE(`ldap://127.0.0.1:${port}`, (err, result) => {
    t.error(err)
    t.ok(result)
    const keys = Object.keys(result)
    t.equal(keys.indexOf('controls'), -1)
    t.end()
  })
})
