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

    // find user by distinguishedName
    if (/^.&.*objectcategory=user.*(distinguishedname)/i.test(filter)) {
      let usernames = /distinguishedname=(cn=.*)\)+/i.exec(filter)[1];
      if (usernames.indexOf(')(') !== -1) {
        // querying multiple users at once
        usernames = usernames.split(')(');
        usernames = usernames.map((u) => {
          const r = u.replace(/distinguishedname=/gi, '');
          return r.replace(/\)/g, '');
        })
      } else {
        // just a single user
        usernames = [usernames.replace(/\)/g, '')];
      }
      usernames.forEach((u) => {
        const user = schema.getByRDN(u);
        if (user) {
          res.send(user);
        }
      });
      /*const user = schema.getByRDN(username.replace(/\)/g, ''));
      res.send(user);*/
      res.end();
      return;
    }

    // query for a user's group membership
    if (/^.member=cn=.*,(\s*)?ou=domain (users|admins),(\s*)?dc=domain/i.test(filter)) {
      const groups =
        schema.getByRDN(filter.replace(/member=/g, '')).attributes.memberOf;
      if (groups) {
        sendGroups(groups);
      }
      res.end();
      return
    }

    // retrieve a group
    if (/^.*objectcategory=group..cn=/i.test(filter) ||
      /^.*objectcategory=group..distinguishedname=cn=/i.test(filter))
    {
      const groupName = /cn=([\w\s]+\*?)/i.exec(filter)[1];
      const result = schema.getGroup(groupName);
      if (result && Array.isArray(result)) {
        // a group wildcard search was done
        result.forEach((r) => res.send(r));
      } else if (result) {
        res.send(result);
      }
      res.end();
      return;
    }

    // query for sub groups
    if (/^.member=cn.*,(\s*)?ou=domain groups,(\s*)?dc=domain/i.test(filter)) {
      const parentGroup = schema.getByRDN(filter.replace(/member=/g, ''));
      const cn = parentGroup.attributes.cn.toLowerCase().replace(/\s/g, '');

      let groups;
      const keys = Object.keys(schema.com.domain['domain groups']);
      for (let k of keys) {
        const g = schema.com.domain['domain groups'][k];
        if (!g.hasOwnProperty('type')) {
          continue;
        }
        if (!g.value.attributes.hasOwnProperty('memberOf')) {
          continue;
        }
        g.value.attributes.memberOf.forEach((sg) => {
          if (sg.attributes.cn.toLowerCase().replace(/\s/g, '') === cn) {
            groups = (!groups) ? [g.value] : [].concat(groups, [g.value]);
          }
        });
      }

      if (groups) {
        sendGroups(groups);
      }
      res.end();
      return;
    }

    // query for all wildcards
    if (/^.+cn=.+\*?../i.test(filter)) {
      const query = /cn=([\w\s]+)\*?.+$/i.exec(filter)[1];
      const results = schema.find(query);
      results.forEach((r) => res.send(r));
      res.end();
      return;
    }

    // no conditions matched so just end the connection
    return res.end();
  });

};