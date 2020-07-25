'use strict'

const async = require('async')

const Group = require('./../models/group')
const utils = require('./utilities')

let ad
let log
let search

/**
 * An interface for querying a specific group for its members and
 * its sub-groups.
 *
 * @private
 * @param {LDAPQueyrParameters} opts LDAP parameters for the query.
 * @param {string} dn The DN of the group to query.
 * @param {function} callback The callback to invoke when done.
 * @constructor
 */
function GroupMembersForDN (opts, dn, callback, stack) {
  this.opts = opts
  this.dn = dn
  this.callback = callback
  this.stack = stack || new Map()
}

/**
 * Used for the `async.forEach` iterator function.
 *
 * @param {object} group An LDAP group entry to parse.
 * @param {function} acb The callback from the `async` library.
 */
GroupMembersForDN.prototype.asyncIterator = function asyncIterator (group, acb) {
  if (this.stack.has(group.cn || group.dn)) {
    return acb()
  }

  if (utils.isGroupResult(group)) {
    log.trace('Adding group "%s" to %s"', group.dn, this.dn)
    const g = new Group(group)
    this.stack.set(g.cn || g.dn, g)

    const getter = new GroupMembersForDN(this.opts, g.dn, (err, nestedGroups) => {
      if (err) {
        return acb(err)
      }
      nestedGroups.forEach((ng) => {
        if (!this.stack.has(ng.cn || ng.dn)) {
          this.stack.set(ng.cn || ng.dn, ng)
        }
      })
      acb()
    }, this.stack)
    getter.getMembers()
  } else {
    acb()
  }
}

/**
 * Used for the `async.forEach` completion callback.
 *
 * @param {Error} err
 */
GroupMembersForDN.prototype.asyncCallback = function asyncCallback (err) {
  if (err) {
    return this.callback(err)
  }

  const groups = Array.from(this.stack.values())
  log.trace(
    'Group "%s" has %d group(s). Groups: %j',
    this.dn, groups.length, groups.map(g => g.dn)
  )
  this.callback(err, groups)
}

/**
 * Should be the only method you need to invoke. It uses the configuration
 * created during construction to lookup the desired group's information and
 * then send the results to the configured callback.
 */
GroupMembersForDN.prototype.getMembers = function getMembers () {
  // Ensure that a valid DN was provided. Otherwise abort the search.
  if (!this.dn) {
    const error = new Error('No distinguishedName (dn) specified for group membership retrieval.')
    log.trace(error)
    ad.emit('error', error)
    return this.callback(error)
  }

  //  Note: Microsoft provides a 'Transitive Filter' for querying nested groups.
  //        i.e. (member:1.2.840.113556.1.4.1941:=<userDistinguishedName>)
  //        However this filter is EXTREMELY slow. Recursively querying ActiveDirectory
  //        is typically 10x faster.
  const localOpts = Object.assign(
    {},
    this.opts,
    {
      filter: '(member=' + utils.parseDistinguishedName(this.dn) + ')',
      scope: 'sub',
      attributes: utils.joinAttributes(
        this.opts.attributes || ad.defaultAttributes.group,
        ['groupType']
      )
    }
  )

  search(localOpts, (err, results) => {
    if (err) {
      this.callback(err)
      return
    }

    async.forEach(
      results,
      this.asyncIterator.bind(this),
      this.asyncCallback.bind(this)
    )
  })
}

/**
 * A wrapper for {@link GroupMembershipForDN} to provide compatibility with
 * the original `getGroupMembershipForDN` function. Note: the `stack`
 * parameter is ultimately not used. It seems to have been present for *if*
 * you wanted to do some memoization. But we *always* want to do that.
 *
 * @private
 * @param {LDAPQueryParameters} [opts] The parameters to use for the query.
 * @param {string} dn The DN for the group of interest.
 * @param {array} [stack] Useless. Put whatever you want, it'll be ignored.
 * @param {function} callback The callback to invoke when done.
 */
function getGroupMembershipForDN (opts, dn, stack, callback) {
  let _opts = opts || {}
  let _dn = dn
  let _cb = callback

  if (typeof stack === 'function') {
    _cb = stack
  }
  if (typeof dn === 'function') {
    _cb = dn
    _dn = opts
    _opts = {}
  }
  if (typeof opts === 'string') {
    _dn = opts
    _opts = {}
  }
  log.trace('getGroupMembershipForDN(%j,%s)', _opts, _dn)

  const getter = new GroupMembersForDN(_opts, _dn, _cb)
  return getter.getMembers()
}

module.exports = function init ($ad, $log) {
  ad = $ad
  log = $log
  search = require('./search')(ad, log)
  return getGroupMembershipForDN
}
