'use strict'

const util = require('util')
const ldap = require('ldapjs')

/**
 * <p>Implements ldapjs.RDN which is the core of every ldapjs.DN object.
 * This is just a simple wrapper to allow us make a simple string like
 * "username" behave in the manner ldapjs.Server expects.</p>
 *
 * @param name {string} The string to turn into a RDN.
 * @constructor
 */
function FakeRDN (name) {
  ldap.RDN.apply(this)
  this.attrs.dn = {
    name: 'dn',
    order: 0,
    value: name
  }
  this.spLead = 0
  this.spTrail = 0
}
util.inherits(FakeRDN, ldap.RDN)

module.exports = FakeRDN
