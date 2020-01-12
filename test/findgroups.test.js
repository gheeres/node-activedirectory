'use strict'

const tap = require('tap')
const ActiveDirectory = require('../index')
const config = require('./config')
const serverFactory = require('./mockServer')
const settings = require('./settings').findGroups

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

tap.test('#findGroups()', t => {
  settings.groups.forEach((group) => {
    const len = group.results.length
    const query = (group.query.filter) ? group.query.filter : group.query
    t.test(`should return ${len} groups for query '${query}'`, t => {
      const expectedResults = group.results
      t.context.ad.findGroups(query, function (err, groups) {
        t.error(err)
        t.type(groups, Array)
        t.equal(groups.length, len)

        const cns = groups.map((g) => g.cn)
        cns.forEach(cn => t.true(expectedResults.includes(cn)))
        t.end()
      })
    })
  })

  t.test('should return default group attributes when not specified', t => {
    const defaultAttributes = ActiveDirectory.defaultAttributes.group
    const group = settings.groups[0]
    t.context.ad.findGroups(group.query, function (err, groups) {
      t.error(err)
      t.type(groups, Array)

      groups.forEach((group) => {
        const attributes = Object.keys(group)
        t.true(attributes.length <= defaultAttributes.length)
        attributes.forEach(attr => t.true(defaultAttributes.includes(attr)))
      })

      t.end()
    })
  })

  t.test('should return default group attributes when no filter is specified', t => {
    const defaultAttributes = ActiveDirectory.defaultAttributes.group
    t.context.ad.findGroups({}, function (err, groups) {
      t.error(err)
      t.type(groups, Array)

      groups.forEach((group) => {
        const attributes = Object.keys(group)
        t.true(attributes.length <= defaultAttributes.length)
        attributes.forEach(attr => t.true(defaultAttributes.includes(attr)))
      })

      t.end()
    })
  })

  t.end()
})

tap.test('#findGroups(opts)', t => {
  t.test('should include groups/membership if opts.includeMembership[] = [ \'all\' ]', t => {
    const group = settings.groups[0]
    const opts = {
      includeMembership: ['all'],
      filter: group.query
    }
    t.context.ad.findGroups(opts, function (err, groups) {
      t.error(err)
      t.type(groups, Array)

      groups.forEach((group) => {
        t.ok(group.groups)
      })

      t.end()
    })
  })

  t.test('should include groups/membership if opts.includeMembership[] = [ \'group\' ]', t => {
    const group = settings.groups[0]
    const opts = {
      includeMembership: ['group'],
      filter: group.query
    }
    t.context.ad.findGroups(opts, function (err, groups) {
      t.error(err)
      t.type(groups, Array)

      groups.forEach((group) => {
        t.ok(group.groups)
      })

      t.end()
    })
  })

  t.test('should not include groups/membership if opts.includeMembership disabled', t => {
    const group = settings.groups[0]
    const opts = {
      includeMembership: false,
      filter: group.query
    }
    t.context.ad.findGroups(opts, function (err, groups) {
      t.error(err)
      t.type(groups, Array)

      groups.forEach((group) => {
        t.notOk(group.groups)
      })

      t.end()
    })
  })

  t.test('should return only requested attributes', t => {
    const group = settings.groups[0]
    const opts = {
      attributes: ['cn'],
      filter: group.query
    }
    t.context.ad.findGroups(opts, function (err, groups) {
      t.error(err)
      t.type(groups, Array)

      groups.forEach((group) => {
        const keys = Object.keys(group)
        t.deepEqual(keys, opts.attributes)
      })

      t.end()
    })
  })

  t.end()
})
