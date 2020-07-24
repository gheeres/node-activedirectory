'use strict'

const tap = require('tap')
const ActiveDirectory = require('../index').promiseWrapper
const config = require('./config')
const serverFactory = require('./mockServer')
const settings = require('./settings').findGroup

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

tap.test('#findGroup()', t => {
  ['cn', 'dn'].forEach((groupAttribute) => {
    const groupName = settings.groupName[groupAttribute]
    t.test(`should return user for (${groupAttribute} ${groupName}`, t => {
      return t.context.ad.findGroup(settings.groupName[groupAttribute])
        .then((group) => {
          t.ok(group)
        })
        .catch(t.error)
    })
  })

  t.test('should return undefined if the group doesn\'t exist', t => {
    return t.context.ad.findGroup('!!!NON-EXISTENT GROUP!!!')
      .then((group) => {
        t.is(group, undefined)
      })
      .catch(t.error)
  })

  t.test('should return default group attributes when not specified', t => {
    const defaultAttributes = t.context.ad.defaultAttributes.group
    return t.context.ad.findGroup(settings.groupName.dn)
      .then((group) => {
        t.ok(group)

        const attributes = Object.keys(group)
        t.deepEqual(attributes, defaultAttributes)
      })
      .catch(t.error)
  })

  t.end()
})

tap.test('#findGroup(opts)', t => {
  t.test('should use the custom opts.filter if provided', t => {
    const opts = {
      filter: settings.opts.custom
    }
    const groupName = settings.groupName.dn
    return t.context.ad.findGroup(opts, groupName)
      .then((group) => {
        t.notEqual(group.dn.toLowerCase(), groupName.toLowerCase())
      })
      .catch(t.error)
  })

  t.test('should include groups/membership if opts.includeMembership[] = [ \'all\' ]', t => {
    const opts = {
      includeMembership: ['all']
    }
    return t.context.ad.findGroup(opts, settings.groupName.dn)
      .then((group) => {
        t.ok(group)
        const cns = group.groups.map((group) => {
          return group.cn
        })
        settings.groups.forEach(group => t.true(cns.includes(group)))
      })
      .catch(t.error)
  })

  t.test('should include groups/membership if opts.includeMembership[] = [ \'group\' ]', t => {
    const opts = {
      includeMembership: ['group']
    }
    return t.context.ad.findGroup(opts, settings.groupName.dn)
      .then((group) => {
        t.ok(group)
        const cns = group.groups.map((group) => {
          return group.cn
        })
        settings.groups.forEach(group => t.true(cns.includes(group)))
      })
      .catch(t.error)
  })

  t.test('should return expected groups/membership if opts.includeMembership enabled', t => {
    const opts = {
      includeMembership: ['group', 'all']
    }
    return t.context.ad.findGroup(opts, settings.groupName.dn)
      .then((group) => {
        t.ok(group)
        const cns = group.groups.map((group) => {
          return group.cn
        })
        settings.groups.forEach(group => t.true(cns.includes(group)))
      })
      .catch(t.error)
  })

  t.test('should return only the first group if more than one result returned', t => {
    const opts = {
      filter: settings.opts.multipleFilter
    }
    return t.context.ad.findGroup(opts, '' /* ignored since we're setting our own filter */)
      .then((group) => {
        t.ok(group)
        t.false(Array.isArray(group))
      })
      .catch(t.error)
  })

  t.test('should return only requested attributes', t => {
    const opts = {
      attributes: ['createdTimestamp']
    }
    return t.context.ad.findGroup(opts, settings.groupName.dn)
      .then((group) => {
        t.ok(group)

        const keys = Object.keys(group)
        t.deepEqual(keys, opts.attributes)
      })
      .catch(t.error)
  })

  t.end()
})
