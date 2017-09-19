'use strict'
/* eslint-env node, mocha */
/* eslint-disable no-unused-expressions */

const expect = require('chai').expect
const ActiveDirectory = require('../index')
const config = require('./config')

let server = require('./mockServer')

describe('Range Limiting', function () {
  let ad
  const settings = require('./settings').findGroups

  before(function (done) {
    server(function (s) {
      ad = new ActiveDirectory(config)
      server = s
      done()
    })
  })

  it('should limit search results', function (done) {
    const opts = {
      sizeLimit: 1,
      filter: `(memberOf=${settings.groups[1].query.filter})`
    }
    ad.find(opts, function (err, results) {
      expect(err).to.be.null
      expect(results).to.not.be.null
      expect(results.groups.length).to.equal(1)
      done()
    })
  })
})
