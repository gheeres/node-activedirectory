'use strict'

const tap = require('tap')
const ActiveDirectory = require('../index').promiseWrapper
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
      return t.context.ad.findGroups(query)
        .then((groups) => {
          t.type(groups, Array)
          t.equal(groups.length, len)

          const cns = groups.map((g) => g.cn)
          cns.forEach(cn => t.true(expectedResults.includes(cn)))
        })
        .catch(t.error)
    })
  })

  t.test('should return default group attributes when not specified', t => {
    const defaultAttributes = t.context.ad.defaultAttributes.group
    const group = settings.groups[0]
    return t.context.ad.findGroups(group.query)
      .then((groups) => {
        t.type(groups, Array)

        groups.forEach((group) => {
          const attributes = Object.keys(group)
          t.true(attributes.length <= defaultAttributes.length)
          attributes.forEach(attr => t.true(defaultAttributes.includes(attr)))
        })
      })
      .catch(t.error)
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
    return t.context.ad.findGroups(opts)
      .then((groups) => {
        t.type(groups, Array)

        groups.forEach((group) => {
          t.ok(group.groups)
        })
      })
      .catch(t.error)
  })

  t.test('should include groups/membership if opts.includeMembership[] = [ \'group\' ]', t => {
    const group = settings.groups[0]
    const opts = {
      includeMembership: ['group'],
      filter: group.query
    }
    return t.context.ad.findGroups(opts)
      .then((groups) => {
        t.type(groups, Array)

        groups.forEach((group) => {
          t.ok(group.groups)
        })
      })
      .catch(t.error)
  })

  t.test('should not include groups/membership if opts.includeMembership disabled', t => {
    const group = settings.groups[0]
    const opts = {
      includeMembership: false,
      filter: group.query
    }
    return t.context.ad.findGroups(opts)
      .then((groups) => {
        t.type(groups, Array)

        groups.forEach((group) => {
          t.notOk(group.groups)
        })
      })
      .catch(t.error)
  })

  t.test('should return only requested attributes', t => {
    const group = settings.groups[0]
    const opts = {
      attributes: ['cn'],
      filter: group.query
    }
    return t.context.ad.findGroups(opts)
      .then((groups) => {
        t.type(groups, Array)

        groups.forEach((group) => {
          const keys = Object.keys(group)
          t.deepEqual(keys, opts.attributes)
        })
      })
      .catch(t.error)
  })

  t.end()
})
