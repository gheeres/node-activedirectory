'use strict'

const async = require('async')

const Group = require('./../models/group')
const utils = require('./utilities')

const defaultGroupFilter = '(objectClass=group)(!(objectClass=computer))(!(objectClass=user))(!(objectClass=person))'

let ad
let log
let search

/**
 * An interface for finding groups within the LDAP tree.
 *
 * @private
 * @param {LDAPQueryParameters} opts The LDAP query to issue.
 * @param {function} callback The callback to invoke when done.
 * @constructor
 */
function GroupsFinder (opts, callback) {
  this.opts = opts
  // this.groupName = groupName;
  this.callback = callback

  this.filter = defaultGroupFilter
  if (this.opts && this.opts.filter && /^\(&/.test(this.opts.filter)) {
    // already have a compound filter (likely from the `findGroup` method)
    this.filter = this.opts.filter
  } else if (this.opts && this.opts.filter) {
    this.filter = '(&' + defaultGroupFilter + utils.getCompoundFilter(this.opts.filter) + ')'
  } else {
    this.filter = `(&${this.filter})`
  }

  this.groups = []
  this.localOpts = {}
}

/**
 * The interator function for `async.forEach`.
 *
 * @param {object} result An LDAP search entry result.
 * @param {function} acb The internal callback from `async.forEach`.
 */
GroupsFinder.prototype.asyncIterator = function asyncIterator (result, acb) {
  if (!utils.isGroupResult(result)) {
    return acb()
  }
  const group = new Group(
    // not localOpts because it includes extra attributes just for the query
    utils.pickAttributes(result, this.opts.attributes || ad.defaultAttributes.group)
  )
  log.trace('found group for query "%s". group: %j',
    utils.truncateLogOutput(this.filter), group)
  this.groups.push(group)

  // get users in group if desired
  if (utils.includeGroupMembershipFor(this.localOpts, 'group')) {
    const getUsersCallback = (err, groups) => {
      if (err) {
        return acb(err)
      }

      group.groups = groups
      ad.emit('group', group)
      acb()
    }

    ad.getGroupMembershipForDN(this.localOpts, group.dn, getUsersCallback)
  } else {
    ad.emit('group', group)
    acb()
  }
}

/**
 * The completion callback for `async.forEach'.
 *
 * @param {Error} err
 */
GroupsFinder.prototype.asyncCallback = function asyncCallback (err) {
  if (err) {
    return this.callback(err)
  }

  log.trace('%d group(s) found for query "%s". Groups: %j',
    this.groups.length, utils.truncateLogOutput(this.localOpts.filter), this.groups)

  ad.emit('groups', this.groups)
  this.callback(null, this.groups)
}

/**
 * Should be the only method you need to invoke. It uses the configuration
 * created during construction to issue the search.
 */
GroupsFinder.prototype.find = function find () {
  this.localOpts = Object.assign(
    {},
    this.opts,
    {
      filter: this.filter,
      scope: 'sub',
      attributes: utils.joinAttributes(
        this.opts.attributes || ad.defaultAttributes.group,
        utils.getRequiredLdapAttributesForGroup(this.opts)
      )
    }
  )

  search(this.localOpts, this.onComplete.bind(this))
}

/**
 * Invoked when the search has completed.
 *
 * @param {Error} err
 * @param {array} results
 */
GroupsFinder.prototype.onComplete = function onComplete (err, results) { // jshint -W071
  if (err) {
    if (this.callback) {
      this.callback(err)
    }
    return
  }

  if (results.length === 0) {
    log.trace('Group not found for query "%s"', utils.truncateLogOutput(this.filter))
    if (this.callback) {
      this.callback(err, [])
    }
    return
  }

  async.forEach(
    results,
    this.asyncIterator.bind(this),
    this.asyncCallback.bind(this)
  )
}

/**
 * Wraps {@link GroupsFinder} so as to be compatible with the original
 * `findGroups` function.
 *
 * @param {LDAPQueryParameters} [opts]
 * @param {function} callback The callback to invoke when done.
 */
function findGroups (opts, callback) {
  let _opts = opts || {}
  let _cb = callback

  if (typeof opts === 'function') {
    _cb = opts
    _opts = ''
  }
  if (typeof opts === 'string' && opts.length > 0) {
    _opts = {
      filter: '(&' + defaultGroupFilter + utils.getCompoundFilter(opts) + ')'
    }
  }
  log.trace('findGroups(%j)', _opts)

  const groupsFinder = new GroupsFinder(_opts, _cb)
  return groupsFinder.find()
}

module.exports = function init ($ad, $log) {
  ad = $ad
  log = $log
  search = require('./search')(ad, log)

  return findGroups
}
