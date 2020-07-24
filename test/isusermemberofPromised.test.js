'use strict'

const tap = require('tap')
const ActiveDirectory = require('../index').promiseWrapper
const config = require('./config')
const serverFactory = require('./mockServer')
const settings = require('./settings').isUserMemberOf

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

tap.test('should return true if the username (sAMAccountName) is a member of the groupName (commonName)', t => {
  return t.context.ad.isUserMemberOf(settings.sAMAccountName, settings.groupName.cn)
    .then((isMember) => t.true(isMember))
    .catch(t.error)
})

tap.test('should return true if the username (sAMAccountName) is a member of the groupName (distinguishedName)', t => {
  return t.context.ad.isUserMemberOf(settings.sAMAccountName, settings.groupName.dn)
    .then((isMember) => t.true(isMember))
    .catch(t.error)
})

tap.test('should return true if the username (userPrincipalName) is a member of the groupName (commonName)', t => {
  return t.context.ad.isUserMemberOf(settings.userPrincipalName, settings.groupName.cn)
    .then((isMember) => t.true(isMember))
    .catch(t.error)
})

tap.test('should return true if the username (userPrincipalName) is a member of the groupName (distinguishedName)', t => {
  return t.context.ad.isUserMemberOf(settings.userPrincipalName, settings.groupName.dn)
    .then((isMember) => t.true(isMember))
    .catch(t.error)
})

tap.test('should return true if the username (distinguishedName) is a member of the groupName (commonName)', t => {
  return t.context.ad.isUserMemberOf(settings.dn, settings.groupName.cn)
    .then((isMember) => t.true(isMember))
    .catch(t.error)
})

tap.test('should return true if the username (distinguishedName) is a member of the groupName (distinguishedName)', t => {
  return t.context.ad.isUserMemberOf(settings.dn, settings.groupName.dn)
    .then((isMember) => t.true(isMember))
    .catch(t.error)
})

tap.test('should return false if the username (sAMAccountName) is not a member of the groupName', t => {
  return t.context.ad.isUserMemberOf(settings.sAMAccountName, '!!!NON-EXISTENT GROUP!!!')
    .then((isMember) => t.false(isMember))
    .catch(t.error)
})

tap.test('should return false if the username (userPrincipalName) is not a member of the groupName', t => {
  return t.context.ad.isUserMemberOf(settings.userPrincipalName, '!!!NON-EXISTENT GROUP!!!')
    .then((isMember) => t.false(isMember))
    .catch(t.error)
})

tap.test('should return false if the username (distinguishedName) is not a member of the groupName', t => {
  return t.context.ad.isUserMemberOf(settings.dn, '!!!NON-EXISTENT GROUP!!!')
    .then((isMember) => t.false(isMember))
    .catch(t.error)
})

tap.test('should return true if the username is a member of a nested groupName', t => {
  return t.context.ad.isUserMemberOf(settings.sAMAccountName, settings.groupName.nested)
    .then((isMember) => t.true(isMember))
    .catch(t.error)
})
