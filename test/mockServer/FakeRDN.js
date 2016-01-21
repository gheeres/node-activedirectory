'use strict';

const util = require('util');
const ldap = require('ldapjs');

function FakeRDN(name) {
  ldap.RDN.apply(this);
  this.attrs.dn = {
    name: 'dn',
    order: 0,
    value: name
  };
  this.spLead = 0;
  this.spTrail = 0;
}
util.inherits(FakeRDN, ldap.RDN);

module.exports = FakeRDN;