'use strict'

const tap = require('tap')
const ActiveDirectory = require('../index')
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
      t.context.ad.getUsersForGroup(group.dn, function (err, users) {
        t.error(err)
        t.ok(users)
        t.equal(users.length, len)

        const dns = users.map((u) => {
          return u.dn.toLowerCase().replace(/[\s\\]/g, '')
        })
        group.users.forEach((source) => {
          const testStr = source.toLowerCase().replace(/\s/g, '')
          t.true(dns.includes(testStr))
        })

        t.end()
      })
    })

    t.test(`should return ${len} users for (commonName) ${group.cn}`, t => {
      t.context.ad.getUsersForGroup(group.cn, function (err, users) {
        t.error(err)
        t.ok(users)
        t.equal(users.length, len)

        const dns = users.map((u) => {
          return u.dn.toLowerCase().replace(/[\s\\]/g, '')
        })
        group.users.forEach((source) => {
          const testStr = source.toLowerCase().replace(/\s/g, '')
          t.true(dns.includes(testStr))
        })

        t.end()
      })
    })
  })

  t.test('should return empty users if groupName doesn\'t exist', t => {
    t.context.ad.getUsersForGroup('!!!NON-EXISTENT GROUP!!!', function (err, users) {
      t.error(err)
      t.is(users, undefined)
      t.end()
    })
  })

  t.test('should return default user attributes when not specified', t => {
    const defaultAttributes = [
      'dn', 'distinguishedName',
      'userPrincipalName', 'sAMAccountName', /* 'objectSID', */ 'mail',
      'lockoutTime', 'whenCreated', 'pwdLastSet', 'userAccountControl',
      'employeeID', 'sn', 'givenName', 'initials', 'cn', 'displayName',
      'comment', 'description'
    ]
    const group = settings.groups[0]
    t.context.ad.getUsersForGroup(group.dn, function (err, users) {
      t.error(err)
      t.ok(users)
      users.forEach((u) => {
        t.equal(Object.keys(u).length, defaultAttributes.length)
      })
      t.end()
    })
  })

  t.end()
})

tap.test('#getUsersForGroup(opts)', t => {
  t.test('should return only requested attributes', t => {
    const opts = {
      attributes: ['createTimeStamp']
    }
    const group = settings.groups[0]
    t.context.ad.getUsersForGroup(opts, group.dn, function (err, users) {
      t.error(err)
      t.ok(users)
      t.equal(users.length, group.users.length)

      users.forEach((u) => {
        const keys = Object.keys(u)
        t.equal(keys.length, opts.attributes.length)
        keys.forEach((k) => {
          t.true(opts.attributes.includes(k))
        })
      })

      t.end()
    })
  })

  t.end()
})
