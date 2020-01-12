'use strict'

const tap = require('tap')
const ldapjs = require('ldapjs')
const ActiveDirectory = require('../index')
const config = require('./config')
const serverFactory = require('./mockServer')
const settings = require('./settings').find

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

tap.test('#find()', t => {
  settings.queries.forEach(function (query) {
    const userCount = query.results.users.length
    const groupCount = query.results.groups.length
    const otherCount = query.results.other.length
    const _query = (query.query.filter) ? query.query.filter : query.query

    t.test(`should return ${userCount} users, ${groupCount} groups, ${otherCount} other for query '${_query}'`, t => {
      t.context.ad.find(_query, function (err, results) {
        t.error(err)
        t.type(results, 'object')

        const keys = ['users', 'groups', 'other']
        for (const key of keys) {
          const expectedResults = query.results[key]
          const actualResults = results[key]

          t.is(actualResults.length, expectedResults.length)

          const cns = actualResults.map((result) => {
            return result.cn
          })
          expectedResults.forEach((expectedResult) => {
            const filteredResults = cns.filter((cn) => {
              return cn
                .toLowerCase()
                .indexOf(expectedResult.toLowerCase()) !== -1
            })
            t.is(filteredResults.length, 1)
          })
        }

        t.end()
      })
    })
  })

  t.test('should return default query attributes when not specified', t => {
    const defaultAttributes = {
      groups: ActiveDirectory.defaultAttributes.group,
      users: ActiveDirectory.defaultAttributes.user
    }
    defaultAttributes.other = Array.from(new Set(
      [].concat(defaultAttributes.groups, defaultAttributes.users)
    ))

    const query = settings.queries[0]
    t.context.ad.find(query.query, function (err, results) {
      t.error(err)
      t.type(results, 'object')

      const keys = ['users', 'groups', 'other']
      for (const key of keys) {
        const keyAttributes = defaultAttributes[key]
        results[key].forEach((result) => {
          const attributes = Object.keys(result)
          t.true(attributes.length <= keyAttributes.length)
          attributes.forEach((attribute) => {
            t.true(keyAttributes.includes(attribute))
          })
        })
      }

      t.end()
    })
  })

  t.end()
})

tap.test('#find(opts)', t => {
  t.test('should include groups/membership groups and users if opts.includeMembership[] = [ \'all\' ]', t => {
    const query = settings.queries[0]
    const opts = {
      includeMembership: ['all'],
      filter: query.query
    }
    t.context.ad.find(opts, function (err, results) {
      t.error(err)
      t.type(results, 'object')

      results.users.forEach((user) => {
        t.ok(user.groups)
      })

      results.groups.forEach((group) => {
        t.ok(group.groups)
      })

      results.other.forEach((other) => {
        t.notOk(other.groups)
      })

      t.end()
    })
  })

  t.test('should include groups/membership for groups if opts.includeMembership[] = [ \'group\' ]', t => {
    const query = settings.queries[0]
    const opts = {
      includeMembership: ['group'],
      filter: query.query
    }
    t.context.ad.find(opts, function (err, results) {
      t.error(err)
      t.type(results, 'object')

      results.groups.forEach((group) => {
        t.ok(group.groups)
      });

      ['users', 'other'].forEach((key) => {
        const items = results[key]
        items.forEach((item) => {
          t.notOk(item.groups)
        })
      })

      t.end()
    })
  })

  t.test('should include groups/membership for users if opts.includeMembership[] = [ \'user\' ]', t => {
    const query = settings.queries[0]
    const opts = {
      includeMembership: ['user'],
      filter: query.query
    }
    t.context.ad.find(opts, function (err, results) {
      t.error(err)
      t.type(results, 'object')

      results.users.forEach((user) => {
        t.ok(user.groups)
      });

      ['groups', 'other'].forEach((key) => {
        const items = results[key]
        items.forEach((item) => {
          t.notOk(item.groups)
        })
      })

      t.end()
    })
  })

  t.test('should not include groups/membership if opts.includeMembership disabled', t => {
    const query = settings.queries[0]
    const opts = {
      includeMembership: false,
      filter: query.query
    }
    t.context.ad.find(opts, function (err, results) {
      t.error(err)
      t.type(results, 'object')

      const keys = ['users', 'groups', 'other']
      for (const key of keys) {
        const items = results[key]
        items.forEach((item) => {
          t.notOk(item.groups)
        })
      }

      t.end()
    })
  })

  t.test('should return only requested attributes', t => {
    const query = settings.queries[0]
    const opts = {
      attributes: ['cn'],
      filter: query.query
    }
    t.context.ad.find(opts, function (err, results) {
      t.error(err)
      t.type(results, 'object')

      const keys = ['users', 'groups', 'other']
      for (const key of keys) {
        results[key].forEach((result) => {
          const keys = Object.keys(result)
          t.true(keys.length <= opts.attributes.length)
          if (keys.length === opts.attributes.length) {
            t.deepEqual(keys, opts.attributes)
          }
        })
      }

      t.end()
    })
  })

  t.test('should return err (ConnectionError) when connection timeouts', t => {
    new ActiveDirectory({
      url: 'ldap://example.com',
      connectTimeout: 100
    }).find({}, function (err, result) {
      t.type(err, ldapjs.ConnectionError)
      t.notOk(result)
      t.end()
    })
  })

  t.end()
})
