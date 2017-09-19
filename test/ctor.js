'use strict'
/* eslint-env node, mocha */
/* eslint-disable no-unused-expressions */

const expect = require('chai').expect
const ActiveDirectory = require('../index')
const config = require('./config')

let server = require('./mockServer')

describe('ctor method', function () {
  it('should support legacy parameters (url, baseDN, username, password)', function (done) {
    const ad = new ActiveDirectory(config.url, config.baseDN, config.username, config.password)
    expect(ad.baseDN).to.equal(config.baseDN)
    expect(ad.opts.url).to.equal(config.url)
    expect(ad.opts.bindDN).to.equal(config.username)
    expect(ad.opts.bindCredentials).to.equal(config.password)
    done()
  })

  it('should set parameters from configuration object', function (done) {
    const ad = new ActiveDirectory(config)
    expect(ad.baseDN).to.equal(config.baseDN)
    expect(ad.opts.url).to.equal(config.url)
    expect(ad.opts.bindDN).to.equal(config.username)
    expect(ad.opts.bindDN).to.equal(config.username)
    expect(ad.opts.bindCredentials).to.equal(config.password)
    done()
  })

  it('should replace default user attributes if specified', function (done) {
    const ad = new ActiveDirectory(Object.assign({}, config, {
      attributes: {
        user: [ 'mycustomuserattribute' ]
      }
    }))
    const defaultAttributes = ad.defaultAttributes || {}
    expect(defaultAttributes.user.length).to.equal(1)
    expect(defaultAttributes.group.length).to.be.gt(0)
    done()
  })

  it('should replace default group attributes if specified', function (done) {
    const ad = new ActiveDirectory(Object.assign({}, config, {
      attributes: {
        group: [ 'mycustomgroupattribute' ]
      }
    }))
    const defaultAttributes = ad.defaultAttributes || {}
    expect(defaultAttributes.group.length).to.equal(1)
    expect(defaultAttributes.user.length).to.be.gt(0)
    done()
  })

  it('should throw an InvalidCredentialsError exception if the username/password are incorrect.', function (done) {
    let ad
    function doTest () {
      ad.findUser('unknown', function (err, user) {
        expect(err).to.not.be.null
        expect(err).to.be.an.instanceof(Error)
        expect(err.name).to.equal('InvalidCredentialsError')
        done()
      })
    }

    server(function (s) {
      ad = new ActiveDirectory(Object.assign({}, config, {
        password: 'TheWrongPassword!',
        username: 'AnInvalidUsername'
      }))
      server = s
      doTest()
    })
  })

  it('should parse ldapjs options into the opts property', function (done) {
    const ad = new ActiveDirectory(Object.assign({}, config, {
      tlsOptions: {foo: 'bar'},
      paged: true
    }))

    expect(ad.opts.paged).to.be.true
    expect(ad.opts.tlsOptions).to.exist
    expect(ad.opts.tlsOptions.foo).to.equal('bar')
    done()
  })
})
