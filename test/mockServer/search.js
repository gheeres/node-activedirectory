'use strict';

const ldap = require('ldapjs');
const schema = require('./schema');
const domainUsers = schema.com.domain['domain users'];
const domainAdmins = schema.com.domain['domain admins'];
const baseDN = 'dc=domain,dc=com';

module.exports = function search(server, settings) {
  server.search(baseDN, function(req, res, next) {
    const filter = req.filter.toString();

    function sendGroups(groups) {
      groups.forEach(g => res.send(g));
    }

    function getUser(username) {
      const users = [];
      for (let key of Object.keys(domainAdmins)) {
        if (key !== 'type') {
          users.push(domainAdmins[key].value);
        }
      }
      for (let key of Object.keys(domainUsers)) {
        if (key !== 'type') {
          users.push(domainUsers[key].value);
        }
      }
      let result;
      for (let user of users) {
        if (user.attributes.sAMAccountName === username) {
          result = user;
          break;
        }
      }
      return result;
    }

    function isInGroup(user, group) {
      let result;
      for (let g of user.value.attributes.memberOf) {
        const dn = g.attributes.distinguishedName.toLowerCase();
        if (dn.indexOf(group.toLowerCase()) !== -1) {
          result = true;
          break;
        }
      }
      return result;
    }

    // non-existence checks
    if (filter.indexOf('!!!') !== -1) {
      return res.end();
    }

    // find a user
    if (/^.&.objectcategory=user.*(samaccountname|useprincipalname)/i.test(filter)) {
      let username = /(?:((?:\(samaccountname=.*\))|(?:\(userprincipalname=.*\))))/i
        .exec(filter)[1].split('=')[1];
      // userPrincipalName filter
      username = (username.indexOf('@')) ? username.split('@')[0] : username;
      // sAMAccountName filter
      username = (username.indexOf(')')) ? username.split(')')[0] : username;
      const user = getUser(username);
      res.send(user);
      res.end();
      return;
    }

    // query for a user's group membership
    if (/^.member=cn=.*,(\s*)?ou=domain (users|admins),(\s*)?dc=domain/i.test(filter)) {
      const groups =
        schema.getByRDN(filter.replace(/member=/g, '')).attributes.memberOf;
      sendGroups(groups);
      res.end();
      return
    }

    // check for group existence
    if (/^.*objectcategory=group..cn=/i.test(filter) ||
      /^.*objectcategory=group..distinguishedname=cn=/i.test(filter))
    {
      const group = /cn=([\w\s]+)/i.exec(filter)[1];
      res.send(schema.com.domain['domain groups'][group.toLowerCase()].value);
      res.end();
      return;
    }

    // query for sub groups
    if (/^.member=cn.*,(\s*)?ou=domain groups,(\s*)?dc=domain/i.test(filter)) {
      /*const group = /^.member=cn=(.*),(\s+)?ou=domain groups/i.exec(filter)[1];
      const members = [];*/

      // not implemented

      res.end();
      return;
    }

    // no conditions matched so just end the connection
    return res.end();
  });

};