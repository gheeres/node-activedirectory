'use strict'

const tap = require('tap')
const ldapjs = require('ldapjs')
const ActiveDirectory = require('../index')
const username = 'username'
const password = 'password'

tap.test('#authenticate()', t => {
  t.test('should return err (ENOTFOUND) on invalid hostname (dns)', t => {
    const ad = new ActiveDirectory({
      url: 'ldap://invalid.domain.💩'
    })
    ad.authenticate(username, password, function (err, auth) {
      t.type(err, Error)
      t.equal(err.code, 'ENOTFOUND')
      t.false(auth)
      t.end()
    })
  })

  t.test('should return err (ECONNREFUSED) on non listening port', t => {
    const ad = new ActiveDirectory({
      url: 'ldap://127.0.0.1:65535/'
    })
    ad.authenticate(username, password, function (err, auth) {
      t.type(err, Error)
      t.equal(err.code, 'ECONNREFUSED')
      t.false(auth)
      t.end()
    })
  })

  t.test('should return err (ConnectionError) when connection timeouts', t => {
    const ad = new ActiveDirectory({
      url: 'ldap://example.com',
      connectTimeout: 1
    })
    ad.authenticate(username, password, function (err, auth) {
      t.type(err, ldapjs.ConnectionError)
      t.false(auth)
      t.end()
    })
  })

  t.end()
})
