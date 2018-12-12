'use strict'

const util = require('util')
const AD = require('./activedirectory')

function promiseWrapper (instance, method, args) {
  function promise (resolve, reject) {
    const cb = function (err, result) {
      return (err) ? reject(err) : resolve(result)
    }

    const _args = [].concat(Array.from(args), cb)
    AD.prototype[method].apply(instance, _args)
  }

  return new Promise(promise)
}

/**
 * A wrapper object for {@link ActiveDirectory}. This wrapper exposes all of the
 * methods as `Promise` returning methods.
 *
 * For details on any of the methods, reference the {@link ActiveDirectory}
 * documentation; simply ignore the `callback` parameters.
 *
 * @example <caption>Authenticate a user</caption>
 *
 * const AD = require('activedirectory/lib/adpromise');
 * const ad = new AD({
 *   url: 'ldap://example.com',
 *   baseDN: 'dc=example,dc=com',
 *   username: 'reader',
 *   password: 'supersecret'
 * });
 *
 * ad.find('joe_user')
 *   .then((user) => {
 *     ad.authenticate(user.dn, 'letmein')
 *       .then((result) => {
 *         console.log(`login result: ${result}`);
 *       })
 *       .catch(console.error);
 *    })
 *    .catch(console.error);
 *
 * @constructor
 */
function PromisedAD () {
  AD.apply(this, arguments)
}
util.inherits(PromisedAD, AD)

PromisedAD.prototype.authenticate = function authenticate (username, password) {
  return promiseWrapper(this, 'authenticate', arguments)
}

PromisedAD.prototype.find = function find (opts) {
  return promiseWrapper(this, 'find', arguments)
}

PromisedAD.prototype.findDeletedObjects = function findDeletedObjects (opts) {
  return promiseWrapper(this, 'findDeletedObjects', arguments)
}

PromisedAD.prototype.findGroup = function findGroup (opts, groupName) {
  return promiseWrapper(this, 'findGroup', arguments)
}

PromisedAD.prototype.findGroups = function findGroups (opts) {
  return promiseWrapper(this, 'findGroups', arguments)
}

PromisedAD.prototype.findUser = function findUser (opts, username, includeMembership) {
  return promiseWrapper(this, 'findUser', arguments)
}

PromisedAD.prototype.findUsers = function findUsers (opts, includeMembership) {
  return promiseWrapper(this, 'findUsers', arguments)
}

// private
PromisedAD.prototype.getDistinguishedNames = function gdn (opts, filter) {
  return promiseWrapper(this, 'getDistinguishedNames', arguments)
}

// private
PromisedAD.prototype.getGroupDistinguishedName = function ggdn (opts, groupName) {
  return promiseWrapper(this, 'getGroupDistinguishedName', arguments)
}

// private
PromisedAD.prototype.getGroupMembershipForDN = function ggmfd (opts, dn) {
  return promiseWrapper(this, 'getGroupMembershipForDN', arguments)
}

PromisedAD.prototype.getGroupMembershipForGroup = function ggmfg (opts, groupName) {
  return promiseWrapper(this, 'getGroupMembershipForGroup', arguments)
}

PromisedAD.prototype.getGroupMembershipForUser = function ggmfu (opts, username) {
  return promiseWrapper(this, 'getGroupMembershipForUser', arguments)
}

PromisedAD.prototype.getRootDSE = function getRootDSE (url, attributes) {
  return promiseWrapper(this, 'getRootDSE', arguments)
}

PromisedAD.getRootDSE = function staticGetRootDSE (url, attributes) {
  function promise (resolve, reject) {
    const args = [url, attributes]
    args.push((err, result) => {
      return (err) ? reject(err) : resolve(result)
    })
    return AD.getRootDSE.apply(PromisedAD.prototype, args)
  }
  return new Promise(promise)
}

// private
PromisedAD.prototype.getUserDistinguishedName = function gudn (opts, username) {
  // Since this is used internally by ActiveDirectory, it can't return a
  // Promise.
  // TODO: make the internal call handle a Promise
  return AD.prototype.getUserDistinguishedName.apply(this, arguments)
  // return promiseWrapper(this, 'getUserDistinguishedNames', arguments);
}

PromisedAD.prototype.getUsersForGroup = function getUsersForGroup (opts, groupName) {
  return promiseWrapper(this, 'getUsersForGroup', arguments)
}

PromisedAD.prototype.groupExists = function groupExists (opts, groupName) {
  return promiseWrapper(this, 'groupExists', arguments)
}

PromisedAD.prototype.isUserMemberOf = function isUserMemberOf (opts, username, groupName) {
  return promiseWrapper(this, 'isUserMemberOf', arguments)
}

PromisedAD.prototype.userExists = function userExists (opts, username) {
  return promiseWrapper(this, 'userExists', arguments)
}

module.exports = PromisedAD
