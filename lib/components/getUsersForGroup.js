'use strict'

const async = require('async')

const User = require('./../models/user')
const utils = require('./utilities')

let ad
let log
let search

/**
 * Breaks the large array into chucks of the specified size.
 * @private
 * @param {array} arr The array to break into chunks
 * @param {number} chunkSize The size of each chunk.
 * @returns {array} The resulting array containing each chunk.
 */
function chunk (arr, chunkSize) {
  const result = []
  for (let i = 0, j = arr.length; i < j; i += chunkSize) {
    result.push(arr.slice(i, i + chunkSize))
  }
  return result
}

/**
 * An interface for retrieving a list of users within a given group.
 *
 * @private
 * @param {LDAPQueryParameters} opts LDAP parameters for the query.
 * @param {string} groupName The group to get the user list for.
 * @param {function} callback The function to invoke when done.
 * @constructor
 */
function GroupUsersFinder (opts, groupName, callback) {
  this.opts = opts
  this.groupName = groupName
  this.callback = callback

  this.chunks = []
  this.chunksProcessed = 0
  this.users = new Map()
  if (Object.prototype.hasOwnProperty.call(this.opts, 'recursionstack') === false) {
    this.opts.recursionstack = []
  }
}

/**
 * Iterator funciton for the `async.forEach` call within the `async.each` call.
 * This iterator is used to process each individual member and queue them
 * to the result map.
 *
 * @param {object} member A user search entry result.
 * @param {function} acb Internal callback function for the `async.forEach`.
 */
GroupUsersFinder.prototype.forEachIter = function forEachIter (member, acb) {
  // If a user, no groupType will be specified
  if (!member.groupType) {
    const user = new User(
      utils.pickAttributes(member, this.opts.attributes || ad.defaultAttributes.user)
    )
    ad.emit('user', user)
    this.users.set(member.dn, user)
    return acb()
  }

  // We have a group, so we recursively get the users in it
  // but escape if group is already in the stack, which happens when group A is member of group B and group B is member of group A
  if (this.opts.recursionstack.indexOf(member.dn) === -1) {
    // prefer to use member.dn instead member.cn, because cn may not be unique
    ad.getUsersForGroup(this.opts, member.dn, (err, nestedUsers) => {
      if (err) throw err
      nestedUsers.forEach(u => this.users.set(u.dn, u))
      acb()
    })
  } else {
    acb()
  }
}

/**
 * Iterator function for the `async.each` call used to process the "chunks" of
 * user results.
 *
 * @param {array} members An array of user search entry results.
 * @param {function} acb Internal callback function for `async.each`.
 */
GroupUsersFinder.prototype.eachIterator = function eachIterator (members, acb) {
  // We're going to build up a bulk LDAP query so we can reduce
  // the number of round trips to the server. We need to get
  // additional details about each 'member' to determine if
  // it is a group or another user. If it's a group, we need
  // to recursively retrieve the members of that group.
  let filter = members.reduce((prev, curr) => {
    const res = '(distinguishedName=' + utils.parseDistinguishedName(curr) + ')'
    return (prev) ? prev + res : res
  }, null)
  filter = `(&(|(objectCategory=User)(objectCategory=Group))(|${filter}))`

  const localOpts = {
    filter: filter,
    scope: 'sub',
    attributes: utils.joinAttributes(
      this.opts.attributes || ad.defaultAttributes.user || [],
      utils.getRequiredLdapAttributesForUser(this.opts),
      ['groupType']
    )
  }

  search(localOpts, (err, members) => {
    if (err) {
      return acb(err)
    }

    const asyncCallback = (err) => {
      if (this.chunks.length > 1) {
        this.chunksProcessed += 1
        log.trace(
          'Finished processing chunk %d/%d',
          this.chunksProcessed, this.chunks.length
        )
      }
      acb(err)
    }

    // Parse the results in parallel.
    async.forEach(members, this.forEachIter.bind(this), asyncCallback)
  })
}

/**
 * This is the only method you should need to invoke. It uses the configuration
 * created during construction to find the users and return them via the
 * provided callback.
 */
GroupUsersFinder.prototype.find = function find () {
  const groupAttributes = Object.assign(
    {},
    this.opts,
    {
      attributes: utils.joinAttributes(
        this.opts.attributes || ad.defaultAttributes.group, ['member']
      )
    }
  )

  ad.findGroup(groupAttributes, this.groupName, (err, group) => {
    if (err) {
      return this.callback(err)
    } else if (!group) {
      return this.callback(null, group)
    }

    this.opts.recursionstack.push(group.dn)
    if (!Array.isArray(group.member)) {
      group.member = (group.member) ? [group.member] : []
    }

    // for groups with many users, we split them up and process
    // them in parallel for efficiency
    this.chunks = chunk(group.member, ad.pageSize)
    if (this.chunks.length > 1) {
      log.trace('Splitting %d member(s) of "%s" into %d parallel chunks',
        group.member.length, this.groupName, this.chunks.length)
    }

    const eachCallback = (err) => {
      log.trace('%d user(s) belong in the group "%s"', this.users.size, this.groupName)
      this.callback(err, Array.from(this.users.values()))
    }

    async.each(this.chunks, this.eachIterator.bind(this), eachCallback)
  })
}

/**
 * A wrapper for {@link GroupUsersFinder} to provide compatibility
 * with the original `getUsersForGroup` method.
 *
 * @private
 * @param {LDAPQueryParameters} [opts] LDAP parameters for the query.
 * @param {string} groupName The group to get the user list for.
 * @param {function} callback The function to invoke when done.
 */
function getUsersForGroup (opts, groupName, callback) {
  let _opts = opts || {}
  let _groupName = groupName
  let _cb = callback

  if (typeof groupName === 'function') {
    _cb = groupName
    _groupName = opts
    _opts = {}
  }

  const finder = new GroupUsersFinder(_opts, _groupName, _cb)
  return finder.find()
}

module.exports = function init ($ad, $log) {
  ad = $ad
  log = $log
  search = require('./search')(ad, log)
  return getUsersForGroup
}
