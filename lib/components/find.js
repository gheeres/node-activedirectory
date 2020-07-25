'use strict'

const async = require('async')

const User = require('./../models/user')
const Group = require('./../models/group')

const utils = require('./utilities')

let ad
let log
let search

/**
 * An interface for performing generic LDAP queries and returning the results,
 * via a callback, as an object broken up into groups, users, and other
 * categories.
 *
 * @private
 * @param {LDAPQueryParameters} opts The LDAP query to issue.
 * @param {function} callback The callback to invoke on error or success.
 * @constructor
 */
function Finder (opts, callback) {
  this.opts = opts
  this.callback = callback

  this.result = {
    groups: [],
    users: [],
    other: []
  }
}

/**
 * Invoked after the `async.forEach` in {@link Finder#find} has completed.
 * @param {Error} err
 */
Finder.prototype.asyncCallback = function asyncCallback (err) {
  if (err) {
    if (this.callback) {
      this.callback(err)
    }
    return
  }
  log.trace('%d group(s), %d user(s), %d other found for query "%s". Results: %j',
    this.result.groups.length,
    this.result.users.length,
    this.result.other.length,
    this.opts.filter,
    this.result
  )
  ad.emit('groups', this.result.groups)
  ad.emit('users', this.result.users)

  if (this.callback) {
    this.callback(null, this.result)
  }
}

/**
 * The function invoked by the `async.forEach` in {@link Finder#find}. This
 * determines the type of result, `item`, and feeds it to the appropriate
 * parsing method.
 *
 * @param {object} item A search entry result.
 * @param {function} cb A callback sent in by the `async` library to invoke
 * when the iteration has completed.
 */
Finder.prototype.asyncIterator = function asyncIterator (item, cb) {
  if (utils.isGroupResult(item)) {
    this.parseGroupResult(item, cb)
  } else if (utils.isUserResult(item)) {
    this.parseUserResult(item, cb)
  } else {
    this.parseOtherResult(item, cb)
  }
}

/**
 * The only method you should need to invoke on an instance. It uses the
 * configuration created during construction to issue a search against the
 * LDAP store. The results are returned via the callback supplied to the
 * constructor.
 */
Finder.prototype.find = function find () {
  const localOpts = Object.assign({ scope: 'sub' }, this.opts, {
    attributes: utils.joinAttributes(
      this.opts.attributes || [],
      ad.defaultAttributes.group,
      ad.defaultAttributes.user,
      utils.getRequiredLdapAttributesForGroup(this.opts),
      utils.getRequiredLdapAttributesForUser(this.opts),
      ['objectCategory']
    )
  })

  search(localOpts, (err, results) => {
    if (err) {
      if (this.callback) {
        this.callback(err)
      }
      return
    }

    if (results.length === 0) {
      log.trace(
        'No results found for query "%s"',
        utils.truncateLogOutput(localOpts.filter)
      )
      if (this.callback) {
        this.callback()
      }
      ad.emit('done')
      return
    }

    // Parse the results in parallel.
    async.forEach(
      results,
      this.asyncIterator.bind(this),
      this.asyncCallback.bind(this)
    )
  })
}

/**
 * Parses a group search entry result.
 *
 * @param {object} item A search entry result.
 * @param {function} cb The `async` callback to invoke when done.
 */
Finder.prototype.parseGroupResult = function parseGroupResult (item, cb) {
  const groupAttributes = this.opts.attributes || ad.defaultAttributes.group
  const group = new Group(utils.pickAttributes(item, groupAttributes))
  this.result.groups.push(group)

  // get user group memberships if desired
  if (utils.includeGroupMembershipFor(this.opts, 'group')) {
    ad.getGroupMembershipForDN(this.opts, group.dn, (err, groups) => {
      if (err) {
        return cb(err)
      }
      group.groups = groups
      ad.emit('group', group)
      cb()
    })
  } else {
    ad.emit('group', group)
    cb()
  }
}

/**
 * Parses an "other", e.g. "computer", search entry result.
 *
 * @param {object} item A search entry result.
 * @param {function} cb The `async` callback to invoke when done.
 */
Finder.prototype.parseOtherResult = function parseOtherResult (item, cb) {
  const groupAttributes = this.opts.attributes || ad.defaultAttributes.group
  const userAttributes = this.opts.attributes || ad.defaultAttributes.user
  const other = utils.pickAttributes(item,
    this.opts.attributes ||
    [].concat(userAttributes, groupAttributes).filter((ele, i, arr) => {
      return i === arr.indexOf(ele)
    })
  )
  this.result.other.push(other)
  ad.emit('other', other)
  cb()
}

/**
 * Parses an user search entry result.
 *
 * @param {object} item A search entry result.
 * @param {function} cb The `async` callback to invoke when done.
 */
Finder.prototype.parseUserResult = function parseUserResult (item, cb) {
  const userAttributes = this.opts.attributes || ad.defaultAttributes.user
  const user = new User(utils.pickAttributes(item, userAttributes))
  this.result.users.push(user)

  // get user group memberships if desired
  if (utils.includeGroupMembershipFor(this.opts, 'user')) {
    ad.getGroupMembershipForDN(this.opts, user.dn, (err, groups) => {
      if (err) {
        return cb(err)
      }
      user.groups = groups
      ad.emit('user', user)
      cb()
    })
  } else {
    ad.emit('user', user)
    cb()
  }
}

/**
 * Wraps an instance of {@link Finder} so as to be backward compatible with
 * the original `find` function.
 *
 * @private
 * @param {(LDAPQueryParameters|string)} [opts] Optional LDAP query string
 * parameters to execute. Optionally, if only a string is provided, then the
 * string is assumed to be an LDAP filter.
 * @param {function} callback The callback to execute when completed.
 */
function find (opts, callback) {
  let _opts = opts
  let _cb = callback

  if (typeof opts === 'function') {
    _cb = opts
    _opts = {}
  }
  if (typeof opts === 'string') {
    _opts = { filter: opts }
  }
  log.trace('find(%j)', _opts)
  const finder = new Finder(_opts, _cb)
  return finder.find()
}

module.exports = function init ($ad, $log) {
  ad = $ad
  log = $log
  search = require('./search')(ad, log)
  return find
}
