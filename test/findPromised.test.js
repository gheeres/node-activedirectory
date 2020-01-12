'use strict'

const tap = require('tap')
const ActiveDirectory = require('../index').promiseWrapper
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
    tap.test(`should return ${userCount} users, ${groupCount} groups, ${otherCount} other for query '${_query}'`, t => {
      return t.context.ad.find(_query)
        .then((results) => {
          t.ok(results)

          const keys = ['users', 'groups', 'other']
          for (const key of keys) {
            const expectedResults = query.results[key]
            const actualResults = results[key]

            t.equal(actualResults.length, expectedResults.length)

            const cns = actualResults.map((result) => {
              return result.cn
            })
            expectedResults.forEach((expectedResult) => {
              const filteredResults = cns.filter((cn) => {
                return cn
                  .toLowerCase()
                  .indexOf(expectedResult.toLowerCase()) !== -1
              })
              t.equal(filteredResults.length, 1)
            })
          }
        })
        .catch(t.error)
    })
  })

  t.test('should return default query attributes when not specified', t => {
    const defaultAttributes = {
      groups: t.context.ad.defaultAttributes.group,
      users: t.context.ad.defaultAttributes.user
    }
    defaultAttributes.other = Array.from(new Set(
      [].concat(defaultAttributes.groups, defaultAttributes.users)
    ))

    const query = settings.queries[0]
    return t.context.ad.find(query.query)
      .then((results) => {
        t.ok(results)

        const keys = ['users', 'groups', 'other']
        for (const key of keys) {
          const keyAttributes = defaultAttributes[key]
          results[key].forEach((result) => {
            const attributes = Object.keys(result)
            t.true(attributes.length <= keyAttributes.length)
            attributes.forEach((attribute) => t.true(keyAttributes.includes(attribute)))
          })
        }
      })
      .catch(t.error)
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
    return t.context.ad.find(opts)
      .then((results) => {
        t.ok(results)

        results.users.forEach((user) => {
          t.ok(user.groups)
        })

        results.groups.forEach((group) => {
          t.ok(group.groups)
        })

        results.other.forEach((other) => {
          t.notOk(other.groups)
        })
      })
      .catch(t.error)
  })

  t.test('should include groups/membership for groups if opts.includeMembership[] = [ \'group\' ]', t => {
    const query = settings.queries[0]
    const opts = {
      includeMembership: ['group'],
      filter: query.query
    }
    return t.context.ad.find(opts)
      .then((results) => {
        t.ok(results)

        results.groups.forEach((group) => t.ok(group.groups))

        const keys = ['users', 'other']
        for (const key of keys) {
          const items = results[key]
          items.forEach((item) => {
            t.notOk(item.groups)
          })
        }
      })
      .catch(t.error)
  })

  t.test('should include groups/membership for users if opts.includeMembership[] = [ \'user\' ]', t => {
    const query = settings.queries[0]
    const opts = {
      includeMembership: ['user'],
      filter: query.query
    }
    return t.context.ad.find(opts)
      .then((results) => {
        t.ok(results)

        results.users.forEach((user) => t.ok(user.groups))

        const keys = ['groups', 'other']
        for (const key of keys) {
          const items = results[key]
          items.forEach((item) => {
            t.notOk(item.groups)
          })
        }
      })
      .catch(t.error)
  })

  t.test('should not include groups/membership if opts.includeMembership disabled', t => {
    const query = settings.queries[0]
    const opts = {
      includeMembership: false,
      filter: query.query
    }
    return t.context.ad.find(opts)
      .then((results) => {
        t.ok(results)

        const keys = ['users', 'groups', 'other']
        for (const key of keys) {
          const items = results[key]
          items.forEach((item) => {
            t.notOk(item.groups)
          })
        }
      })
      .catch(t.error)
  })

  t.test('should return only requested attributes', t => {
    const query = settings.queries[0]
    const opts = {
      attributes: ['cn'],
      filter: query.query
    }
    return t.context.ad.find(opts)
      .then((results) => {
        t.ok(results)

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
      })
      .catch(t.error)
  })

  t.end()
})
