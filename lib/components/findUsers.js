'use strict'

const async = require('async')
const utils = require('./utilities')

const User = require('./../models/user')

let ad
let log
let search

const defaultUserFilter = '(|(objectClass=user)(objectClass=person))(!(objectClass=computer))(!(objectClass=group))'

/**
 * An interface for finding users within the LDAP tree.
 *
 * @private
 * @param {LDAPQueryParameters} opts LDAP parameters to use.
 * @param {boolean} includeMembership Whether or not to include a users's
 * group memberships.
 * @param {function} callback Callback to invoke when done.
 * @constructor
 */
function UsersFinder (opts, includeMembership, callback) {
  this.opts = opts
  this.includeMembership = includeMembership
  this.callback = callback

  this.users = []
}

/**
 * Used as the `async.forEach` iterator function.
 *
 * @param {object} result A user search result entry.
 * @param {function} acb The `async` callback to invoke.
 */
UsersFinder.prototype.asyncIterator = function asyncIterator (result, acb) {
  if (!utils.isUserResult(result)) {
    return acb()
  }

  const user = new User(
    utils.pickAttributes(result, this.opts.attributes || ad.defaultAttributes.user)
  )
  this.users.push(user)

  // get group memberships if desired
  if (utils.includeGroupMembershipFor(this.opts, 'user') || this.includeMembership) {
    ad.getGroupMembershipForDN(this.opts, user.dn, (err, groups) => {
      if (err) {
        return acb(err)
      }

      user.groups = groups
      ad.emit('user', user)
      acb()
    })
  } else {
    ad.emit('user', user)
    acb()
  }
}

/**
 * Used as the `async.forEach` completion callback.
 *
 * @param {Error} err
 */
UsersFinder.prototype.asyncCallback = function asyncCallback (err) {
  if (err) {
    this.callback(err)
  }

  log.trace('%d user(s) found for query "%s". Users: %j',
    this.users.length, utils.truncateLogOutput(this.opts.filter), this.users
  )
  ad.emit('users', this.users)
  this.callback(null, this.users)
}

/**
 * The only method you should need to invoke. It uses the configuration
 * established during construction to find the users and return them
 * via the provided callback.
 */
UsersFinder.prototype.find = function find () {
  const localOpts = Object.assign(
    {},
    this.opts,
    {
      filter: this.opts.filter || `(&${defaultUserFilter})`,
      scope: 'sub',
      attributes: utils.joinAttributes(
        this.opts.attributes || ad.defaultAttributes.user,
        utils.getRequiredLdapAttributesForUser(this.opts),
        ['objectCategory']
      )
    }
  )

  search(localOpts, (err, results) => {
    if (err) {
      return this.callback(err)
    }

    if (results.length === 0) {
      log.trace('No users found matching query "%s"',
        utils.truncateLogOutput(localOpts.filter))
      return this.callback(null, this.users)
    }

    // Parse the results in parallel.
    async.forEach(results,
      this.asyncIterator.bind(this),
      this.asyncCallback.bind(this)
    )
  })
}

/**
 * A wrapper around {@link UsersFinder} to retain compatibility with
 * the original `findUsers` function.
 *
 * @private
 * @param {LDAPQueryParameters} opts LDAP parameters to use.
 * @param {boolean} includeMembership Whether or not to include a users's
 * group memberships.
 * @param {function} callback The callback to invoke when done.
 */
function findUsers (opts, includeMembership, callback) {
  let _opts = opts
  let _inclMembership = includeMembership
  let _cb = callback

  if (typeof includeMembership === 'function') {
    _cb = includeMembership
    _inclMembership = false
  }
  if (typeof opts === 'function') {
    _cb = opts
    _opts = ''
  }
  if (typeof opts === 'string' && opts.length > 0) {
    _opts = {
      filter: '(&' + defaultUserFilter + utils.getCompoundFilter(opts) + ')'
    }
  }
  log.trace('findUsers(%j,%s)', _opts, _inclMembership)

  const finder = new UsersFinder(_opts, _inclMembership, _cb)
  return finder.find()
}

module.exports = function init ($ad, $log) {
  ad = $ad
  log = $log
  search = require('./search')(ad, log)
  return findUsers
}
