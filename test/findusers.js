'use strict'
/* eslint-env mocha, chai */

const expect = require('chai').expect
const ActiveDirectory = require('../index')
const config = require('./config')

let server = require('./mockServer')

describe('findUsers Method', function () {
  let ad
  const settings = require('./settings').findUsers
  const timeout = 6000 // The timeout in milliseconds before a test is considered failed.

  before(function (done) {
    server(function (s) {
      ad = new ActiveDirectory(config)
      server = s
      done()
    })
  })

  describe('#findUsers()', function () {
    settings.users.forEach(function (user) {
      const len = user.results.length
      const query = (user.query.filter) ? user.query.filter : user.query
      it(`should return ${len} users for query '${query}'`, function (done) {
        this.timeout(timeout)

        ad.findUsers(query, function (err, users) {
          expect(err).to.be.null
          expect(users).to.not.be.null
          expect(Array.isArray(users)).to.be.true
          expect(users.length).to.equal(len)

          const cns = users.map((u) => u.cn).join(' ')
          user.results.forEach((expectedUser) => {
            expect(cns).to.contain(expectedUser)
          })

          done()
        })
      })
    })

    it('should return default user attributes when not specified', function (done) {
      const defaultAttributes = ActiveDirectory.defaultAttributes.user
      const user = settings.users[0]
      ad.findUsers(user.query, function (err, users) {
        expect(err).to.be.null
        expect(users).to.not.be.null
        expect(Array.isArray(users)).to.be.true

        users.forEach((user) => {
          const attributes = Object.keys(user)
          expect(attributes).to.be.any.members(defaultAttributes)
        })

        done()
      })
    })
  })

  describe('#findUsers(opts)', function () {
    it('should include groups/membership if opts.includeMembership[] = [ \'all\' ]', function (done) {
      this.timeout(timeout)

      const user = settings.users[0]
      const opts = {
        includeMembership: [ 'all' ],
        filter: user.query
      }
      ad.findUsers(opts, function (err, users) {
        expect(err).to.be.null
        expect(users).to.not.be.null
        expect(Array.isArray(users)).to.be.true

        users.forEach((user) => {
          expect(user.groups).to.exist
        })

        done()
      })
    })

    it('should include groups/membership if opts.includeMembership[] = [ \'user\' ]', function (done) {
      this.timeout(timeout)

      const user = settings.users[0]
      const opts = {
        includeMembership: [ 'user' ],
        filter: user.query
      }
      ad.findUsers(opts, function (err, users) {
        expect(err).to.be.null
        expect(users).to.not.be.null
        expect(Array.isArray(users)).to.be.true

        users.forEach((user) => {
          expect(user.groups).to.exist
        })

        done()
      })
    })

    it('should not include groups/membership if opts.includeMembership disabled', function (done) {
      const user = settings.users[0]
      const opts = {
        includeMembership: false,
        filter: user.query
      }
      ad.findUsers(opts, function (err, users) {
        expect(err).to.be.null
        expect(users).to.not.be.null
        expect(Array.isArray(users)).to.be.true

        users.forEach((user) => {
          expect(user.groups).to.not.exist
        })

        done()
      })
    })

    it('should return only requested attributes', function (done) {
      const user = settings.users[0]
      const opts = {
        attributes: [ 'cn' ],
        filter: user.query
      }
      ad.findUsers(opts, function (err, users) {
        expect(err).to.be.null
        expect(users).to.not.be.null
        expect(Array.isArray(users)).to.be.true

        users.forEach((user) => {
          const keys = Object.keys(user)
          expect(keys.length).to.equal(opts.attributes.length)
          expect(keys).to.be.members(opts.attributes)
        })

        done()
      })
    })
  })
})

