'use strict'

const tap = require('tap')
const ActiveDirectory = require('../index')
const config = require('./config')
const serverFactory = require('./mockServer')
const settings = require('./settings').getGroupMembershipForUser

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

tap.test('#getGroupMembershipForUser()', t => {
  settings.users.forEach((user) => {
    ['dn', 'userPrincipalName', 'sAMAccountName'].forEach((attr) => {
      const len = user.members.length
      t.test(`should return ${len} groups for ${attr}`, t => {
        t.context.ad.getGroupMembershipForUser(user[attr], function (err, groups) {
          t.error(err)
          t.true(groups.length >= user.members.length)

          const groupNames = groups.map((g) => {
            return g.cn
          })
          user.members.forEach((g) => {
            t.true(groupNames.includes(g))
          })

          t.end()
        })
      })
    })
  })

  t.test('should return empty groups if groupName doesn\'t exist', t => {
    t.context.ad.getGroupMembershipForUser('!!!NON-EXISTENT GROUP!!!', function (err, groups) {
      t.error(err)
      t.type(groups, Array)
      t.equal(groups.length, 0)
      t.end()
    })
  })

  t.test('should return default group attributes when not specified', t => {
    const defaultAttributes = ['objectCategory', 'distinguishedName', 'cn', 'description']
    const user = settings.users[0]
    t.context.ad.getGroupMembershipForUser(user.userPrincipalName, function (err, groups) {
      t.error(err)
      t.ok(groups)

      groups.forEach((g) => {
        const keys = Object.keys(g)
        defaultAttributes.forEach((attr) => {
          t.true(keys.includes(attr))
        })
      })

      t.end()
    })
  })

  t.end()
})

tap.test('#getGroupMembershipForUser(opts)', t => {
  t.test('should return only requested attributes', t => {
    const opts = {
      attributes: ['createTimeStamp']
    }
    const user = settings.users[0]

    t.context.ad.getGroupMembershipForUser(opts, user.userPrincipalName, function (err, groups) {
      t.error(err)
      t.ok(groups)
      t.true(groups.length >= user.members.length)

      groups.forEach((g) => {
        const keys = Object.keys(g)
        keys.forEach((attr) => {
          t.true(opts.attributes.includes(attr))
        })
      })

      t.end()
    })
  })

  t.end()
})
