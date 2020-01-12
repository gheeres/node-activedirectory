'use strict'

const tap = require('tap')
const ActiveDirectory = require('../index')
const config = require('./config')
const serverFactory = require('./mockServer')

tap.test('ctor method', t => {
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

  t.test('should support legacy parameters (url, baseDN, username, password)', t => {
    const localConfig = config(t.context.server.port)
    t.context.ad = new ActiveDirectory(localConfig.url, localConfig.baseDN, localConfig.username, localConfig.password)
    t.is(t.context.ad.baseDN, localConfig.baseDN)
    t.is(t.context.ad.opts.url, localConfig.url)
    t.is(t.context.ad.opts.bindDN, localConfig.username)
    t.is(t.context.ad.opts.bindCredentials, localConfig.password)
    t.end()
  })

  t.test('should set parameters from configuration object', t => {
    const localConfig = config(t.context.server.port)
    t.context.ad = new ActiveDirectory(localConfig)
    t.is(t.context.ad.baseDN, localConfig.baseDN)
    t.is(t.context.ad.opts.url, localConfig.url)
    t.is(t.context.ad.opts.bindDN, localConfig.username)
    t.is(t.context.ad.opts.bindDN, localConfig.username)
    t.is(t.context.ad.opts.bindCredentials, localConfig.password)
    t.end()
  })

  t.test('should replace default user attributes if specified', t => {
    const localConfig = config(t.context.server.port)
    t.context.ad = new ActiveDirectory(Object.assign({}, localConfig, {
      attributes: {
        user: ['mycustomuserattribute']
      }
    }))
    const defaultAttributes = t.context.ad.defaultAttributes || {}
    t.is(defaultAttributes.user.length, 1)
    t.true(defaultAttributes.group.length > 0)
    t.end()
  })

  t.test('should replace default group attributes if specified', t => {
    const localConfig = config(t.context.server.port)
    t.context.ad = new ActiveDirectory(Object.assign({}, localConfig, {
      attributes: {
        group: ['mycustomgroupattribute']
      }
    }))
    const defaultAttributes = t.context.ad.defaultAttributes || {}
    t.is(defaultAttributes.group.length, 1)
    t.true(defaultAttributes.user.length > 0)
    t.end()
  })

  // TODO: Disabled until https://github.com/ldapjs/node-ldapjs/issues/592 is resolved
  // t.test('should throw an InvalidCredentialsError exception if the username/password are incorrect.', t => {
  //   const localConfig = config(t.context.server.port)
  //   t.context.ad = new ActiveDirectory(Object.assign({}, localConfig, {
  //     password: 'TheWrongPassword!',
  //     username: 'AnInvalidUsername'
  //   }))
  //   t.context.ad.findUser('unknown', function (err) {
  //     t.type(err, Error)
  //     t.is(err.name, 'InvalidCredentialsError')
  //     t.end()
  //   })
  // })

  t.test('should parse ldapjs options into the opts property', t => {
    const localConfig = config(t.context.server.port)
    t.context.ad = new ActiveDirectory(Object.assign({}, localConfig, {
      tlsOptions: { enableTrace: false },
      paged: true
    }))

    t.true(t.context.ad.opts.paged)
    t.ok(t.context.ad.opts.tlsOptions)
    t.is(t.context.ad.opts.tlsOptions.enableTrace, false)
    t.end()
  })

  t.end()
})
