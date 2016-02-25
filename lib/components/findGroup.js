'use strict';

const path = require('path');

const modelsPath = path.join(__dirname, '..', 'models');
const Group = require(path.join(modelsPath, 'group'));
const utils = require('./utilities');

let ad;
let log;
let search;

/**
 * An interface for finding groups within the LDAP tree.
 *
 * @private
 * @param {LDAPQueryParameters} opts The LDAP query to issue.
 * @param {string} groupName The group to find (cn or dn).
 * @param {function} callback The callback to invoke when done.
 * @constructor
 */
function GroupFinder(opts, groupName, callback) {
  this.opts = opts;
  this.groupName = groupName;
  this.callback = callback;

  this.filter = (this.opts && this.opts.filter) ?
    this.opts.filter : utils.getGroupQueryFilter(this.groupName);
}

/**
 * Should be the only method you need to invoke. It uses the configuration
 * created during construction to issue the search.
 */
GroupFinder.prototype.find = function find() {
  const localOpts = {
    filter: this.filter,
    scope: 'sub',
    attributes: utils.joinAttributes(
      this.opts.attributes || ad.defaultAttributes.group,
      utils.getRequiredLdapAttributesForGroup(this.opts)
    )
  };

  search(localOpts, this.onComplete.bind(this));
};

/**
 * Invoked when the search has completed.
 *
 * @param {Error} err
 * @param {array} results
 */
GroupFinder.prototype.onComplete = function onComplete(err, results) { // jshint -W071
  if (err) {
    if (this.callback) {
      this.callback(err);
    }
    return;
  }

  if (results.length === 0) {
    log.warn('Group "%s" not found for query "%s"', this.groupName, utils.truncateLogOutput(this.filter));
    if (this.callback) {
      this.callback();
    }
    return;
  }

  const group = new Group(
    utils.pickAttributes(results[0], this.opts.attributes || ad.defaultAttributes.group)
  );
  log.info('%d group(s) found for query "%s". Returning first group: %j',
             results.length, utils.truncateLogOutput(this.filter), group);

  // get users in group if desired
  if (utils.includeGroupMembershipFor(this.opts, 'group')) {
    const getUsersCallback = (err, groups) => {
      if (err) {
        if (this.callback) {
          this.callback();
        }
        return;
      }

      group.groups = groups;
      ad.emit('group', group);
      if (this.callback) {
        this.callback(err, group);
      }
    };

    ad.getGroupMembershipForDN(this.opts, group.dn, getUsersCallback);
  } else {
    ad.emit('group', group);
    if (this.callback) {
      this.callback(err, group);
    }
  }
};

/**
 * Wraps {@link GroupFinder} so as to be compatible with the original
 * `findGroup` function.
 *
 * @param {LDAPQueryParameters} [opts]
 * @param {string} groupName The group (cn) to retrieve. Can optionally be
 * the distinguishedName (dn) of the group.
 * @param {function} callback The callback to invoke when done.
 */
function findGroup(opts, groupName, callback) {
  let _opts = (opts) ? opts : {};
  let _groupName = groupName;
  let _cb = callback;

  if (typeof groupName === 'function') {
    _cb = groupName;
    _groupName = opts;
    _opts = {};
  }
  if (typeof opts === 'string') {
    _groupName = opts;
    _opts = {};
  }
  log.trace('findGroup(%j,%s)', _opts, _groupName);

  const groupFinder = new GroupFinder(_opts, _groupName, _cb);
  return groupFinder.find();
}

module.exports = function init($ad, $log) {
  ad = $ad;
  log = $log;
  search = require('./search')(ad, log);

  return findGroup;
};