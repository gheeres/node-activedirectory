'use strict'

const tap = require('tap')
const ActiveDirectory = require('../index')
const config = require('./config')
const serverFactory = require('./mockServer')

tap.test('Range Limiting', t => {
  const settings = require('./settings').findGroups

  t.beforeEach((done, t) => {
    serverFactory(function (err, server) {
      if (err) return done(err)
      const connectionConfig = config(server.port)
      t.context.ad = new ActiveDirectory(connectionConfig)
      t.context.server = server
      done()
    })
  })

  t.afterEach((done, t) => {
    if (t.context.server) t.context.server.close()
    done()
  })

  t.test('should limit search results', t => {
    const opts = {
      sizeLimit: 1,
      filter: `(memberOf=${settings.groups[1].query.filter})`
    }
    t.context.ad.find(opts, function (err, results) {
      t.error(err)
      t.ok(results)
      t.equal(results.groups.length, 1)
      t.end()
    })
  })

  t.end()
})
