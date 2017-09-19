'use strict'
/* eslint-env node, mocha */
/* eslint-disable no-unused-expressions */

const expect = require('chai').expect
const ActiveDirectory = require('../index')
const config = require('./config')

let server = require('./mockServer')

describe('getRootDSE method', function () {
  let ad

  before(function (done) {
    server(function (s) {
      ad = new ActiveDirectory(config)
      server = s
      done()
    })
  })

  it('should return ECONNREFUSED for closed port', function (done) {
    ActiveDirectory.getRootDSE('ldap://127.0.0.1:389', (err) => {
      expect(err).to.not.be.null
      expect(err).to.be.an.instanceof(Error)
      expect(err.errno).to.equal('ECONNREFUSED')
      done()
    })
  })

  it('should return an error if no url specified', function (done) {
    expect(
      ActiveDirectory.getRootDSE.bind(null, null, () => {})
    ).to.throw(Error)
    done()
  })

  it('should use the instance url property if omitted', function (done) {
    ad.getRootDSE((err, result) => {
      expect(err).to.be.null
      expect(result).to.not.be.undefined
      done()
    })
  })

  it('should return all attributes when none specified', function (done) {
    const attrs = ['dn', 'dnsHostName', 'serverName', 'supportedLDAPVersion']
    ad.getRootDSE('ldap://127.0.0.1:1389', (err, result) => {
      expect(err).to.be.null
      expect(result).to.not.be.undefined
      const keys = Object.keys(result)
      keys.forEach((k) => expect(attrs).to.contain(k))
      done()
    })
  })

  it('should return only specified attributes', function (done) {
    // dn is always returned
    const attrs = ['dn', 'supportedLDAPVersion']
    ad.getRootDSE('ldap://127.0.0.1:1389', attrs, (err, result) => {
      expect(err).to.be.null
      expect(result).to.not.be.undefined
      const keys = Object.keys(result)
      keys.forEach((k) => expect(attrs).to.contain(k))
      done()
    })
  })

  it('should not return the controls attribute', function (done) {
    ad.getRootDSE('ldap://127.0.0.1:1389', (err, result) => {
      expect(err).to.be.null
      expect(result).to.not.be.undefined
      const keys = Object.keys(result)
      expect(keys.indexOf('controls')).to.equal(-1)
      done()
    })
  })
})
