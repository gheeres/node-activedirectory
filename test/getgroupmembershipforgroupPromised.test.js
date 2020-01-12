'use strict'

const tap = require('tap')
const ActiveDirectory = require('../index').promiseWrapper
const config = require('./config')
const serverFactory = require('./mockServer')
const settings = require('./settings').getGroupMembershipForGroup

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

tap.test('#getGroupMembershipForGroup()', t => {
  settings.groups.forEach((group) => {
    ['dn', 'cn'].forEach((groupAttribute) => {
      const len = group.members.length
      const expectedGroup = group[groupAttribute]
      t.test(`should return ${len} groups for (${groupAttribute}) ${expectedGroup}`, t => {
        return t.context.ad.getGroupMembershipForGroup(expectedGroup)
          .then((groups) => {
            t.ok(groups)
            t.type(groups, Array)

            const cns = groups.map((g) => g.cn)
            group.members.forEach(member => t.true(cns.includes(member)))
          })
          .catch(t.error)
      })
    })
  })

  t.test('should return empty groups if groupName doesn\'t exist', t => {
    return t.context.ad.getGroupMembershipForGroup('!!!NON-EXISTENT GROUP!!!')
      .then((groups) => {
        t.is(groups, undefined)
      })
      .catch(t.error)
  })

  t.test('should return default group attributes when not specified', t => {
    const defaultAttributes = t.context.ad.defaultAttributes.group
    const group = settings.groups[0]
    return t.context.ad.getGroupMembershipForGroup(group.dn)
      .then((groups) => {
        t.ok(groups)
        t.type(groups, Array)

        groups.forEach((group) => {
          const keys = Object.keys(group)
          t.equal(keys.length, defaultAttributes.length)
        })
      })
      .catch(t.error)
  })

  t.end()
})

tap.test('#getGroupMembershipForGroup(opts)', t => {
  t.test('should return only requested attributes', t => {
    const opts = {
      attributes: ['createTimeStamp']
    }
    const group = settings.groups[0]
    return t.context.ad.getGroupMembershipForGroup(opts, group.dn)
      .then((groups) => {
        t.ok(groups)
        t.type(groups, Array)
        t.true(groups.length >= group.members.length)

        groups.forEach((group) => {
          const keys = Object.keys(group)
          t.deepEqual(keys, opts.attributes)
        })
      })
      .catch(t.error)
  })

  t.end()
})
