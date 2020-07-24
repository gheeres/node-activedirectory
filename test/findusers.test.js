'use strict'

const tap = require('tap')
const ActiveDirectory = require('../index')
const config = require('./config')
const serverFactory = require('./mockServer')
const settings = require('./settings').findUsers

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

tap.test('#findUsers()', t => {
  settings.users.forEach(function (user) {
    const len = user.results.length
    const query = (user.query.filter) ? user.query.filter : user.query
    t.test(`should return ${len} users for query '${query}'`, t => {
      t.context.ad.findUsers(query, function (err, users) {
        t.error(err)
        t.ok(users)
        t.type(users, Array)
        t.equal(users.length, len)

        const cns = users.map((u) => u.cn).join(' ')
        user.results.forEach((expectedUser) => {
          t.true(cns.includes(expectedUser))
        })

        t.end()
      })
    })
  })

  t.test('should return default user attributes when not specified', t => {
    const defaultAttributes = ActiveDirectory.defaultAttributes.user
    const user = settings.users[0]
    t.context.ad.findUsers(user.query, function (err, users) {
      t.error(err)
      t.ok(users)
      t.type(users, Array)

      users.forEach((user) => {
        const attributes = Object.keys(user)
        attributes.forEach(attr => t.true(defaultAttributes.includes(attr)))
      })

      t.end()
    })
  })

  t.end()
})

tap.test('#findUsers(opts)', t => {
  t.test('should include groups/membership if opts.includeMembership[] = [ \'all\' ]', t => {
    const user = settings.users[0]
    const opts = {
      includeMembership: ['all'],
      filter: user.query
    }
    t.context.ad.findUsers(opts, function (err, users) {
      t.error(err)
      t.ok(users)
      t.type(users, Array)

      users.forEach((user) => {
        t.ok(user.groups)
      })

      t.end()
    })
  })

  t.test('should include groups/membership if opts.includeMembership[] = [ \'user\' ]', t => {
    const user = settings.users[0]
    const opts = {
      includeMembership: ['user'],
      filter: user.query
    }
    t.context.ad.findUsers(opts, function (err, users) {
      t.error(err)
      t.ok(users)
      t.type(users, Array)

      users.forEach((user) => {
        t.ok(user.groups)
      })

      t.end()
    })
  })

  t.test('should not include groups/membership if opts.includeMembership disabled', t => {
    const user = settings.users[0]
    const opts = {
      includeMembership: false,
      filter: user.query
    }
    t.context.ad.findUsers(opts, function (err, users) {
      t.error(err)
      t.ok(users)
      t.type(users, Array)

      users.forEach((user) => {
        t.notOk(user.groups)
      })

      t.end()
    })
  })

  t.test('should return only requested attributes', t => {
    const user = settings.users[0]
    const opts = {
      attributes: ['cn'],
      filter: user.query
    }
    t.context.ad.findUsers(opts, function (err, users) {
      t.error(err)
      t.ok(users)
      t.type(users, Array)

      users.forEach((user) => {
        const keys = Object.keys(user)
        t.deepEqual(keys, opts.attributes)
      })

      t.end()
    })
  })

  t.end()
})
