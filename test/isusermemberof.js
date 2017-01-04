'use strict'
/* eslint-env mocha, chai */

const expect = require('chai').expect
const ActiveDirectory = require('../index')
const config = require('./config')

let server = require('./mockServer')

describe('isUserMemberOf Method', function () {
  let ad
  const settings = require('./settings').isUserMemberOf

  before(function (done) {
    server(function (s) {
      ad = new ActiveDirectory(config)
      server = s
      done()
    })
  })

  it('should return true if the username (sAMAccountName) is a member of the groupName (commonName)', function (done) {
    ad.isUserMemberOf(settings.sAMAccountName, settings.groupName.cn, function (err, isMember) {
      expect(err).to.be.null
      expect(isMember).to.be.true
      done()
    })
  })

  it('should return true if the username (sAMAccountName) is a member of the groupName (distinguishedName)', function (done) {
    ad.isUserMemberOf(settings.sAMAccountName, settings.groupName.dn, function (err, isMember) {
      expect(err).to.be.null
      expect(isMember).to.be.true
      done()
    })
  })

  it('should return true if the username (userPrincipalName) is a member of the groupName (commonName)', function (done) {
    ad.isUserMemberOf(settings.userPrincipalName, settings.groupName.cn, function (err, isMember) {
      expect(err).to.be.null
      expect(isMember).to.be.true
      done()
    })
  })

  it('should return true if the username (userPrincipalName) is a member of the groupName (distinguishedName)', function (done) {
    ad.isUserMemberOf(settings.userPrincipalName, settings.groupName.dn, function (err, isMember) {
      expect(err).to.be.null
      expect(isMember).to.be.true
      done()
    })
  })

  it('should return true if the username (distinguishedName) is a member of the groupName (commonName)', function (done) {
    ad.isUserMemberOf(settings.dn, settings.groupName.cn, function (err, isMember) {
      expect(err).to.be.null
      expect(isMember).to.be.true
      done()
    })
  })

  it('should return true if the username (distinguishedName) is a member of the groupName (distinguishedName)', function (done) {
    ad.isUserMemberOf(settings.dn, settings.groupName.dn, function (err, isMember) {
      expect(err).to.be.null
      expect(isMember).to.be.true
      done()
    })
  })

  it('should return false if the username (sAMAccountName) is not a member of the groupName', function (done) {
    ad.isUserMemberOf(settings.sAMAccountName, '!!!NON-EXISTENT GROUP!!!', function (err, isMember) {
      expect(err).to.be.null
      expect(isMember).to.be.false
      done()
    })
  })

  it('should return false if the username (userPrincipalName) is not a member of the groupName', function (done) {
    ad.isUserMemberOf(settings.userPrincipalName, '!!!NON-EXISTENT GROUP!!!', function (err, isMember) {
      expect(err).to.be.null
      expect(isMember).to.be.false
      done()
    })
  })

  it('should return false if the username (distinguishedName) is not a member of the groupName', function (done) {
    ad.isUserMemberOf(settings.dn, '!!!NON-EXISTENT GROUP!!!', function (err, isMember) {
      expect(err).to.be.null
      expect(isMember).to.be.false
      done()
    })
  })

  it('should return true if the username is a member of a nested groupName', function (done) {
    ad.isUserMemberOf(settings.sAMAccountName, settings.groupName.nested, function (err, isMember) {
      expect(err).to.be.null
      expect(isMember).to.be.true
      done()
    })
  })
})

