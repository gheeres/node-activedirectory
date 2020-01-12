'use strict'

const tap = require('tap')
const ActiveDirectory = require('../index')
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
      t.context.ad.findUser(username, function (err, user) {
        t.error(err)
        t.ok(user)
        t.end()
      })
    })
  })

  t.test('should return undefined if the username doesn\'t exist', t => {
    t.context.ad.findUser('!!!NON-EXISTENT USER!!!', function (err, user) {
      t.error(err)
      t.is(user, undefined)
      t.end()
    })
  })

  t.test('should return default user attributes when not specified', t => {
    const defaultAttributes = ActiveDirectory.defaultAttributes.user
    t.context.ad.findUser(settings.username.userPrincipalName, function (err, user) {
      t.error(err)
      t.ok(user)

      const attributes = Object.keys(user)
      t.deepEqual(attributes, defaultAttributes)

      t.end()
    })
  })

  t.end()
})

tap.test('#findUser(opts)', t => {
  t.test('should use the custom opts.filter if provided', t => {
    const opts = {
      filter: settings.opts.custom
    }
    const username = settings.username.userPrincipalName
    t.context.ad.findUser(opts, username, function (err, user) {
      t.error(err)
      t.ok(user)
      t.notEqual(user.userPrincipalName, username)
      t.end()
    })
  })

  t.test('should include groups/membership if opts.includeMembership[] = [ \'all\' ]', t => {
    const opts = {
      includeMembership: ['all']
    }
    const username = settings.username.userPrincipalName
    t.context.ad.findUser(opts, username, function (err, user) {
      t.error(err)
      t.ok(user)
      t.true(user.groups.length >= settings.groups.length)

      const cns = user.groups.map((g) => g.cn)
      settings.groups.forEach(group => t.true(cns.includes(group)))

      t.end()
    })
  })

  t.test('should include groups/membership if opts.includeMembership[] = [ \'user\' ]', t => {
    const opts = {
      includeMembership: ['user']
    }
    const username = settings.username.userPrincipalName
    t.context.ad.findUser(opts, username, function (err, user) {
      t.error(err)
      t.ok(user)
      t.true(user.groups.length >= settings.groups.length)

      const cns = user.groups.map((g) => g.cn)
      settings.groups.forEach(group => t.true(cns.includes(group)))

      t.end()
    })
  })

  t.test('should return expected groups/membership if opts.includeMembership enabled', t => {
    const opts = {
      includeMembership: ['user', 'all']
    }
    const username = settings.username.userPrincipalName
    t.context.ad.findUser(opts, username, function (err, user) {
      t.error(err)
      t.ok(user)
      t.true(user.groups.length >= settings.groups.length)

      const cns = user.groups.map((g) => g.cn)
      settings.groups.forEach(group => t.true(cns.includes(group)))

      t.end()
    })
  })

  t.test('should return only the first user if more than one result returned', t => {
    const opts = {
      filter: settings.opts.multipleFilter
    }
    t.context.ad.findUser(opts, '' /* ignored since we're setting our own filter */, function (err, user) {
      t.error(err)
      t.ok(user)
      t.false(Array.isArray(user))

      t.end()
    })
  })

  t.test('should return only requested attributes', t => {
    const opts = {
      attributes: ['cn']
    }
    const username = settings.username.userPrincipalName
    t.context.ad.findUser(opts, username, function (err, user) {
      t.error(err)
      t.ok(user)

      const keys = Object.keys(user)
      t.true(keys.length <= opts.attributes.length)
      keys.forEach(key => t.true(opts.attributes.includes(key)))

      t.end()
    })
  })

  // https://github.com/jsumners/node-activedirectory/issues/26
  t.test('should return unique users', t => {
    let count = 0
    // The bug was triggered by using a common options object. The method
    // was creating a pointer to this object and then not updating its
    // internal reference on subsequent calls (because it was already defined).
    const opts = {}
    function findUser (user, cb) {
      t.context.ad.findUser(opts, user, function (err, user) {
        count += 1
        t.error(err)
        cb(user)
      })
    }

    findUser('username', (result) => {
      t.equal(result.sAMAccountName, 'username')
      if (count === 2) t.end()
    })

    findUser('username1', (result) => {
      t.equal(result.sAMAccountName, 'username1')
      if (count === 2) t.end()
    })
  })

  t.end()
})
