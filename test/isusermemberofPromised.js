'use strict'
/* eslint-env mocha, chai */

const expect = require('chai').expect
const ActiveDirectory = require('../index').promiseWrapper
const config = require('./config')

let server = require('./mockServer')

describe('Promised isUserMemberOf Method', function () {
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
    ad.isUserMemberOf(settings.sAMAccountName, settings.groupName.cn)
      .then((isMember) => {
        expect(isMember).to.be.true
        done()
      })
      .catch(done)
  })

  it('should return true if the username (sAMAccountName) is a member of the groupName (distinguishedName)', function (done) {
    ad.isUserMemberOf(settings.sAMAccountName, settings.groupName.dn)
      .then((isMember) => {
        expect(isMember).to.be.true
        done()
      })
      .catch(done)
  })

  it('should return true if the username (userPrincipalName) is a member of the groupName (commonName)', function (done) {
    ad.isUserMemberOf(settings.userPrincipalName, settings.groupName.cn)
      .then((isMember) => {
        expect(isMember).to.be.true
        done()
      })
      .catch(done)
  })

  it('should return true if the username (userPrincipalName) is a member of the groupName (distinguishedName)', function (done) {
    ad.isUserMemberOf(settings.userPrincipalName, settings.groupName.dn)
      .then((isMember) => {
        expect(isMember).to.be.true
        done()
      })
      .catch(done)
  })

  it('should return true if the username (distinguishedName) is a member of the groupName (commonName)', function (done) {
    ad.isUserMemberOf(settings.dn, settings.groupName.cn)
      .then((isMember) => {
        expect(isMember).to.be.true
        done()
      })
      .catch(done)
  })

  it('should return true if the username (distinguishedName) is a member of the groupName (distinguishedName)', function (done) {
    ad.isUserMemberOf(settings.dn, settings.groupName.dn)
      .then((isMember) => {
        expect(isMember).to.be.true
        done()
      })
      .catch(done)
  })

  it('should return false if the username (sAMAccountName) is not a member of the groupName', function (done) {
    ad.isUserMemberOf(settings.sAMAccountName, '!!!NON-EXISTENT GROUP!!!')
      .then((isMember) => {
        expect(isMember).to.be.false
        done()
      })
      .catch(done)
  })

  it('should return false if the username (userPrincipalName) is not a member of the groupName', function (done) {
    ad.isUserMemberOf(settings.userPrincipalName, '!!!NON-EXISTENT GROUP!!!')
      .then((isMember) => {
        expect(isMember).to.be.false
        done()
      })
      .catch(done)
  })

  it('should return false if the username (distinguishedName) is not a member of the groupName', function (done) {
    ad.isUserMemberOf(settings.dn, '!!!NON-EXISTENT GROUP!!!')
      .then((isMember) => {
        expect(isMember).to.be.false
        done()
      })
      .catch(done)
  })

  it('should return true if the username is a member of a nested groupName', function (done) {
    ad.isUserMemberOf(settings.sAMAccountName, settings.groupName.nested)
      .then((isMember) => {
        expect(isMember).to.be.true
        done()
      })
      .catch(done)
  })
})

