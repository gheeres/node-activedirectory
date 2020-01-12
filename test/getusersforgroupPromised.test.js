'use strict'

const tap = require('tap')
const ActiveDirectory = require('../index').promiseWrapper
const config = require('./config')
const serverFactory = require('./mockServer')
const settings = require('./settings').getUsersForGroup

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

tap.test('#getUsersForGroup()', t => {
  settings.groups.forEach((group) => {
    const len = group.users.length
    t.test(`should return ${len} users for (distinguishedName) ${group.dn}`, t => {
      return t.context.ad.getUsersForGroup(group.dn)
        .then((users) => {
          t.ok(users)
          t.equal(users.length, len)

          const dns = users.map((u) => {
            return u.dn.toLowerCase().replace(/[\s\\]/g, '')
          })
          group.users.forEach((source) => {
            const testStr = source.toLowerCase().replace(/\s/g, '')
            t.true(dns.includes(testStr))
          })
        })
        .catch(t.error)
    })

    t.test(`should return ${len} users for (commonName) ${group.cn}`, t => {
      return t.context.ad.getUsersForGroup(group.cn)
        .then((users) => {
          t.ok(users)
          t.equal(users.length, len)

          const dns = users.map((u) => {
            return u.dn.toLowerCase().replace(/[\s\\]/g, '')
          })
          group.users.forEach((source) => {
            const testStr = source.toLowerCase().replace(/\s/g, '')
            t.true(dns.includes(testStr))
          })
        })
        .catch(t.error)
    })
  })

  t.test('should return empty users if groupName doesn\'t exist', t => {
    return t.context.ad.getUsersForGroup('!!!NON-EXISTENT GROUP!!!')
      .then((users) => t.is(users, undefined))
      .catch(t.error)
  })

  t.test('should return default user attributes when not specified', t => {
    const defaultAttributes = t.context.ad.defaultAttributes.user
    const group = settings.groups[0]
    return t.context.ad.getUsersForGroup(group.dn)
      .then((users) => {
        t.ok(users)
        users.forEach((u) => {
          t.equal(Object.keys(u).length, defaultAttributes.length)
        })
      })
      .catch(t.error)
  })

  t.end()
})

tap.test('#getUsersForGroup(opts)', t => {
  t.test('should return only requested attributes', t => {
    const opts = {
      attributes: ['createTimeStamp']
    }
    const group = settings.groups[0]
    return t.context.ad.getUsersForGroup(opts, group.dn)
      .then((users) => {
        t.ok(users)
        t.equal(users.length, group.users.length)

        users.forEach((u) => {
          const keys = Object.keys(u)
          t.equal(keys.length, opts.attributes.length)
          keys.forEach((k) => t.true(opts.attributes.includes(k)))
        })
      })
      .catch(t.error)
  })

  t.end()
})
