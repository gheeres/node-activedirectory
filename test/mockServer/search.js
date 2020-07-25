'use strict'

const schema = require('./schema')
const domainUsers = schema.com.domain['domain users']
const domainAdmins = schema.com.domain['domain admins']
const baseDN = 'dc=domain,dc=com'
const SearchEntry = require('ldapjs/lib/messages/search_entry')

// This is the star of the mockServer show. This method handles all of the
// LDAP search queries issued by the ActiveDirectory client. Each type
// of search query is matched by a regular expression, and each type will
// match only one such expression. The match blocks are ordered in a
// "succeed/fail fast" ordering.

module.exports = function search (server, settings) {
  server.search('rootDSE', function rootDSESearch (req, res, next) {
    res.send({
      dn: '',
      attributes: {
        controls: ['foo'],
        dnsHostName: 'domain.com',
        serverName: 'cn=mock,cn=sites,cn=configuration,dc=domain,dc=com',
        supportedLDAPVersion: 3
      }
    })
  })

  server.search(baseDN, function schemaSearch (req, res, next) {
    const filter = req.filter.toString()

    function sendGroups (groups) {
      groups.forEach(g => res.send(g))
    }

    function getUser (username) {
      const users = []
      for (const key of Object.keys(domainAdmins)) {
        if (key !== 'type') {
          users.push(domainAdmins[key].value)
        }
      }
      for (const key of Object.keys(domainUsers)) {
        if (key !== 'type') {
          users.push(domainUsers[key].value)
        }
      }
      let result
      for (const user of users) {
        if (user.attributes.sAMAccountName === username) {
          result = user
          break
        }
      }
      return result
    }

    // non-existence checks
    if (filter.indexOf('!!!') !== -1) {
      return res.end()
    }

    // find a user
    if (/^.&.objectcategory=user.*(samaccountname|useprincipalname)/i.test(filter)) {
      let username = /(?:((?:\(samaccountname=.*\))|(?:\(userprincipalname=.*\))))/i
        .exec(filter)[1].split('=')[1]
      // userPrincipalName filter
      username = (username.indexOf('@')) ? username.split('@')[0] : username
      // sAMAccountName filter
      username = (username.indexOf(')')) ? username.split(')')[0] : username
      const user = getUser(username)
      res.send(user || new SearchEntry())
      res.end()
      return
    }

    // find user by distinguishedName
    if (/^.&.*objectcategory=user.*(distinguishedname)/i.test(filter)) {
      let usernames = /distinguishedname=(cn=.*)\)+/i.exec(filter)[1]
      if (usernames.indexOf(')(') !== -1) {
        // querying multiple users at once
        usernames = usernames.split(')(')
        usernames = usernames.map((u) => {
          const r = u.replace(/distinguishedname=/gi, '')
          return r.replace(/\)/g, '')
        })
      } else {
        // just a single user
        usernames = [usernames.replace(/\)/g, '')]
      }
      usernames.forEach((u) => {
        const user = schema.getByRDN(u)
        if (user) {
          res.send(user)
        }
      })
      res.end()
      return
    }

    // query for a user's group membership
    if (/^.member=cn=.*,(\s*)?ou=domain (users|admins),(\s*)?dc=domain/i.test(filter)) {
      const groups =
        schema.getByRDN(filter.replace(/member=/g, '')).attributes.memberOf
      if (groups) {
        sendGroups(groups)
      }
      res.end()
      return
    }

    // retrieve a specific group
    if (/^.*objectcategory=group..cn=/i.test(filter) ||
      /^.*objectcategory=group..distinguishedname=cn=/i.test(filter)) {
      const groupName = /cn=([\w\s]+\*?)/i.exec(filter)[1]
      const result = schema.getGroup(groupName)
      if (result && Array.isArray(result)) {
        // a group wildcard search was done
        result.forEach((r) => res.send(r))
      } else if (result) {
        res.send(result)
      }
      res.end()
      return
    }

    // query for sub groups
    if (/^.member=cn.*,(\s*)?ou=domain groups,(\s*)?dc=domain/i.test(filter)) {
      const parentGroup = schema.getByRDN(filter.replace(/member=/g, ''))
      const cn = parentGroup.attributes.cn.toLowerCase().replace(/\s/g, '')

      let groups
      const keys = Object.keys(schema.com.domain['domain groups'])
      for (const k of keys) {
        const g = schema.com.domain['domain groups'][k]
        if (!Object.prototype.hasOwnProperty.call(g, 'type')) {
          continue
        }
        if (!Object.prototype.hasOwnProperty.call(g.value.attributes, 'memberOf')) {
          continue
        }
        g.value.attributes.memberOf.forEach((sg) => {
          if (sg.attributes.cn.toLowerCase().replace(/\s/g, '') === cn) {
            groups = (!groups) ? [g.value] : [].concat(groups, [g.value])
          }
        })
      }

      if (groups) {
        sendGroups(groups)
      }
      res.end()
      return
    }

    // query for groups with filter
    if (/^\(&\(objectclass=group\)\(!/i.test(filter)) {
      const query = filter
        .replace('(&(objectclass=group)(!(objectclass=computer))(!(objectclass=user))(!(objectclass=person))', '')
        .replace(')', '')
      const results = schema.filter(query)
      results.forEach((g) => res.send(g))
      res.end()
      return
    }

    // query for users with filter
    if (/^\(&\(\|\(objectclass=user\)\(/i.test(filter)) {
      const query = filter
        .replace('(&(|(objectclass=user)(objectclass=person))(!(objectclass=computer))(!(objectclass=group))', '')
        .replace(')', '')
      const results = schema.filter(query)
      results.forEach((u) => res.send(u))
      res.end()
      return
    }

    // query for all wildcards
    if (/^.+cn=.+\*?../i.test(filter)) {
      const query = /cn=(\*?[\w\s]+)\*?.+$/i.exec(filter)[1]
      const results = schema.find(query)

      if (req.sizeLimit) {
        results.splice(req.sizeLimit)
      }

      results.forEach((r) => res.send(r))
      res.end()
      return
    }

    // query for simple filter
    if (/^\(.+=.+\)$/i.test(filter)) {
      const results = schema.filter(filter)
      results.forEach((r) => res.send(r))
      res.end()
      return
    }

    // no conditions matched so just end the connection
    return res.end()
  })
}
