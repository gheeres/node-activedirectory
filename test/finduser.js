'use strict'
/* eslint-env node, mocha */
/* eslint-disable no-unused-expressions */

const expect = require('chai').expect
const ActiveDirectory = require('../index')
const config = require('./config')

let server = require('./mockServer')

describe('findUser Method', function () {
  let ad
  const settings = require('./settings').findUser

  before(function (done) {
    server(function (s) {
      ad = new ActiveDirectory(config)
      server = s
      done()
    })
  })

  describe('#findUser()', function () {
    [ 'userPrincipalName', 'sAMAccountName', 'dn' ].forEach((userAttribute) => {
      const username = settings.username[userAttribute]
      it(`should return user for (${userAttribute}) ${username}`, function (done) {
        ad.findUser(username, function (err, user) {
          expect(err).to.be.null
          expect(user).to.not.be.null
          done()
        })
      })
    })

    it('should return undefined if the username doesn\'t exist', function (done) {
      ad.findUser('!!!NON-EXISTENT USER!!!', function (err, user) {
        expect(err).to.be.undefined
        expect(user).to.be.undefined
        done()
      })
    })

    it('should return default user attributes when not specified', function (done) {
      const defaultAttributes = ActiveDirectory.defaultAttributes.user
      ad.findUser(settings.username.userPrincipalName, function (err, user) {
        expect(err).to.be.null
        expect(user).to.not.be.null

        const attributes = Object.keys(user)
        expect(attributes.length).to.equal(defaultAttributes.length)
        expect(attributes).to.be.any.members(defaultAttributes)

        done()
      })
    })
  })

  describe('#findUser(opts)', function () {
    it('should use the custom opts.filter if provided', function (done) {
      const opts = {
        filter: settings.opts.custom
      }
      const username = settings.username.userPrincipalName
      ad.findUser(opts, username, function (err, user) {
        expect(err).to.be.null
        expect(user).to.not.be.null
        expect(user.userPrincipalName).to.not.equal(username)
        done()
      })
    })

    it('should include groups/membership if opts.includeMembership[] = [ \'all\' ]', function (done) {
      const opts = {
        includeMembership: [ 'all' ]
      }
      const username = settings.username.userPrincipalName
      ad.findUser(opts, username, function (err, user) {
        expect(err).to.be.null
        expect(user).to.not.be.null
        expect(user.groups.length).to.be.gte(settings.groups.length)

        const cns = user.groups.map((g) => g.cn)
        expect(cns).to.deep.include.members(settings.groups)

        done()
      })
    })

    it('should include groups/membership if opts.includeMembership[] = [ \'user\' ]', function (done) {
      const opts = {
        includeMembership: [ 'user' ]
      }
      const username = settings.username.userPrincipalName
      ad.findUser(opts, username, function (err, user) {
        expect(err).to.be.null
        expect(user).to.not.be.null
        expect(user.groups.length).to.be.gte(settings.groups.length)

        const cns = user.groups.map((g) => g.cn)
        expect(cns).to.deep.include.members(settings.groups)

        done()
      })
    })

    it('should return expected groups/membership if opts.includeMembership enabled', function (done) {
      const opts = {
        includeMembership: [ 'user', 'all' ]
      }
      const username = settings.username.userPrincipalName
      ad.findUser(opts, username, function (err, user) {
        expect(err).to.be.null
        expect(user).to.not.be.null
        expect(user.groups.length).to.be.gte(settings.groups.length)

        const cns = user.groups.map((g) => g.cn)
        expect(cns).to.deep.include.members(settings.groups)

        done()
      })
    })

    it('should return only the first user if more than one result returned', function (done) {
      const opts = {
        filter: settings.opts.multipleFilter
      }
      ad.findUser(opts, '' /* ignored since we're setting our own filter */, function (err, user) {
        expect(err).to.be.null
        expect(user).to.not.be.null
        expect(Array.isArray(user)).to.be.false

        done()
      })
    })

    it('should return only requested attributes', function (done) {
      const opts = {
        attributes: [ 'cn' ]
      }
      const username = settings.username.userPrincipalName
      ad.findUser(opts, username, function (err, user) {
        expect(err).to.be.null
        expect(user).to.not.be.null

        const keys = Object.keys(user)
        expect(keys.length).to.be.lte(opts.attributes.length)
        expect(keys).to.be.any.members(opts.attributes)

        done()
      })
    })

    // https://github.com/jsumners/node-activedirectory/issues/26
    it('should return unique users', function (done) {
      let count = 0
      // The bug was triggered by using a common options object. The method
      // was creating a pointer to this object and then not updating its
      // internal reference on subsequent calls (because it was already defined).
      const opts = {}
      function findUser (user, cb) {
        ad.findUser(opts, user, function (err, user) {
          count += 1
          if (err) done(err)
          cb(user)
        })
      }

      findUser('username', (result) => {
        expect(result.sAMAccountName).to.equal('username')
        if (count === 2) done()
      })

      findUser('username1', (result) => {
        expect(result.sAMAccountName).to.equal('username1')
        if (count === 2) done()
      })
    })
  })
})
