'use strict'

const tap = require('tap')
const ActiveDirectory = require('../index')
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
      t.context.ad.findGroup(settings.groupName[groupAttribute], function (err, group) {
        t.error(err)
        t.ok(group)
        t.end()
      })
    })
  })

  t.test('should return undefined if the group doesn\'t exist', t => {
    t.context.ad.findGroup('!!!NON-EXISTENT GROUP!!!', function (err, group) {
      t.error(err)
      t.notOk(group)
      t.end()
    })
  })

  t.test('should return default group attributes when not specified', t => {
    const defaultAttributes = ActiveDirectory.defaultAttributes.group
    t.context.ad.findGroup(settings.groupName.dn, function (err, group) {
      t.error(err)
      t.ok(group)

      const attributes = Object.keys(group)
      t.true(attributes.length <= defaultAttributes.length)
      attributes.forEach(attr => t.true(defaultAttributes.includes(attr)))
      t.end()
    })
  })

  t.end()
})

tap.test('#findGroup(opts)', t => {
  t.test('should use the custom opts.filter if provided', t => {
    const opts = {
      filter: settings.opts.custom
    }
    const groupName = settings.groupName.dn
    t.context.ad.findGroup(opts, groupName, function (err, group) {
      t.error(err)
      t.ok(group)
      t.notEqual(group.dn.toLowerCase(), groupName.toLowerCase())
      t.end()
    })
  })

  t.test('should include groups/membership if opts.includeMembership[] = [ \'all\' ]', t => {
    const opts = {
      includeMembership: ['all']
    }
    t.context.ad.findGroup(opts, settings.groupName.dn, function (err, group) {
      t.error(err)
      t.ok(group)
      const cns = group.groups.map((group) => {
        return group.cn
      })
      settings.groups.forEach(group => t.true(cns.includes(group)))
      t.end()
    })
  })

  t.test('should include groups/membership if opts.includeMembership[] = [ \'group\' ]', t => {
    const opts = {
      includeMembership: ['group']
    }
    t.context.ad.findGroup(opts, settings.groupName.dn, function (err, group) {
      t.error(err)
      t.ok(group)
      const cns = group.groups.map((group) => {
        return group.cn
      })
      settings.groups.forEach(group => t.true(cns.includes(group)))
      t.end()
    })
  })

  t.test('should return expected groups/membership if opts.includeMembership enabled', t => {
    const opts = {
      includeMembership: ['group', 'all']
    }
    t.context.ad.findGroup(opts, settings.groupName.dn, function (err, group) {
      t.error(err)
      t.ok(group)
      const cns = group.groups.map((group) => {
        return group.cn
      })
      settings.groups.forEach(group => t.true(cns.includes(group)))
      t.end()
    })
  })

  t.test('should return only the first group if more than one result returned', t => {
    const opts = {
      filter: settings.opts.multipleFilter
    }
    t.context.ad.findGroup(opts, '' /* ignored since we're setting our own filter */, function (err, group) {
      t.error(err)
      t.ok(group)
      t.false(Array.isArray(group))
      t.end()
    })
  })

  t.test('should return only requested attributes', t => {
    const opts = {
      attributes: ['createdTimestamp']
    }
    t.context.ad.findGroup(opts, settings.groupName.dn, function (err, group) {
      t.error(err)
      t.ok(group)

      const keys = Object.keys(group)
      t.equal(keys.length, opts.attributes.length)
      if (keys.length === opts.attributes.length) {
        opts.attributes.forEach(attr => t.true(keys.includes(attr)))
      }
      t.end()
    })
  })

  t.end()
})
