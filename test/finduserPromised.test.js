'use strict'

const tap = require('tap')
const ActiveDirectory = require('../index').promiseWrapper
const config = require('./config')
const serverFactory = require('./mockServer')
const settings = require('./settings').findUser

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

tap.test('#findUser()', t => {
  ['userPrincipalName', 'sAMAccountName', 'dn'].forEach((userAttribute) => {
    const username = settings.username[userAttribute]
    t.test(`should return user for (${userAttribute}) ${username}`, t => {
      return t.context.ad.findUser(username)
        .then((user) => t.ok(user))
        .catch(t.error)
    })
  })

  t.test('should return undefined if the username doesn\'t exist', t => {
    return t.context.ad.findUser('!!!NON-EXISTENT USER!!!')
      .then((user) => t.is(user, undefined))
      .catch(t.error)
  })

  t.test('should return default user attributes when not specified', t => {
    const defaultAttributes = t.context.ad.defaultAttributes.user
    return t.context.ad.findUser(settings.username.userPrincipalName)
      .then((user) => {
        t.ok(user)

        const attributes = Object.keys(user)
        t.deepEqual(attributes, defaultAttributes)
      })
      .catch(t.error)
  })

  t.end()
})

tap.test('#findUser(opts)', t => {
  t.test('should use the custom opts.filter if provided', t => {
    const opts = {
      filter: settings.opts.custom
    }
    const username = settings.username.userPrincipalName
    return t.context.ad.findUser(opts, username)
      .then((user) => {
        t.ok(user)
        t.notEqual(user.userPrincipalName, username)
      })
      .catch(t.error)
  })

  t.test('should include groups/membership if opts.includeMembership[] = [ \'all\' ]', t => {
    const opts = {
      includeMembership: ['all']
    }
    const username = settings.username.userPrincipalName
    return t.context.ad.findUser(opts, username)
      .then((user) => {
        t.ok(user)
        t.true(user.groups.length >= settings.groups.length)

        const cns = user.groups.map((g) => g.cn)
        settings.groups.forEach(group => t.true(cns.includes(group)))
      })
      .catch(t.error)
  })

  t.test('should include groups/membership if opts.includeMembership[] = [ \'user\' ]', t => {
    const opts = {
      includeMembership: ['user']
    }
    const username = settings.username.userPrincipalName
    return t.context.ad.findUser(opts, username)
      .then((user) => {
        t.ok(user)
        t.true(user.groups.length >= settings.groups.length)

        const cns = user.groups.map((g) => g.cn)
        settings.groups.forEach(group => t.true(cns.includes(group)))
      })
      .catch(t.error)
  })

  t.test('should return expected groups/membership if opts.includeMembership enabled', t => {
    const opts = {
      includeMembership: ['user', 'all']
    }
    const username = settings.username.userPrincipalName
    return t.context.ad.findUser(opts, username)
      .then((user) => {
        t.ok(user)
        t.true(user.groups.length >= settings.groups.length)

        const cns = user.groups.map((g) => g.cn)
        settings.groups.forEach(group => t.true(cns.includes(group)))
      })
      .catch(t.error)
  })

  t.test('should return only the first user if more than one result returned', t => {
    const opts = {
      filter: settings.opts.multipleFilter
    }
    return t.context.ad.findUser(opts, '' /* ignored since we're setting our own filter */)
      .then((user) => {
        t.ok(user)
        t.false(Array.isArray(user))
      })
      .catch(t.error)
  })

  t.test('should return only requested attributes', t => {
    const opts = {
      attributes: ['cn']
    }
    const username = settings.username.userPrincipalName
    return t.context.ad.findUser(opts, username)
      .then((user) => {
        t.ok(user)

        const keys = Object.keys(user)
        t.true(keys.length <= opts.attributes.length)
        keys.forEach(key => t.true(opts.attributes.includes(key)))
      })
      .catch(t.error)
  })

  t.end()
})
