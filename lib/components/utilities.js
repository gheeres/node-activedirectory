'use strict'

const ldap = require('ldapjs')

// this module consists of various utility functions that are used
// throughout the ActiveDirectory code

/**
 * Factory to create the LDAP client object.
 *
 * @private
 * @param {String} url The url to use when creating the LDAP client.
 * @param {object} opts The optional LDAP client options.
 * @param {ActiveDirectory} An instance of {@link ActiveDirectory} to pull
 * default values from.
 */
function createClient (url, opts, ad) {
  // Attempt to get Url from this instance.
  const _url = url || ad.url || ad.opts.url
  if (!_url) {
    throw new Error('No url specified for ActiveDirectory client.')
  }

  const ldapOpts = getLdapClientOpts(Object.assign({ url: _url }, (ad && ad.opts) ? ad.opts : {}, opts || {}))
  return ldap.createClient(ldapOpts)
}

/**
 * Gets a properly formatted LDAP compound filter. This is a very simple
 * approach to ensure that the LDAP compound filter is wrapped with an enclosing
 * *()* if necessary. It does not handle parsing of an existing
 * compound ldap filter.
 *
 * @private
 * @param {string} filter The LDAP filter to inspect.
 * @returns {string}
 */
function getCompoundFilter (filter) {
  if (!filter) {
    return false
  }
  if (filter.charAt(0) === '(' && filter.charAt(filter.length - 1) === ')') {
    return filter
  }
  return `(${filter})`
}

/**
 * Gets the ActiveDirectory LDAP query string for a group search.
 *
 * @private
 * @param {string} [groupName] The name of the group to find. Defaults to
 * finding the whole category 'group'.
 * @returns {string}
 */
function getGroupQueryFilter (groupName) {
  if (!groupName) {
    return '(objectCategory=Group)'
  }
  if (isDistinguishedName(groupName)) {
    return '(&(objectCategory=Group)(distinguishedName=' +
      parseDistinguishedName(groupName) + '))'
  }
  return `(&(objectCategory=Group)(cn=${groupName}))`
}

/**
 * From the list of options, retrieves the ldapjs client specific options.
 *
 * @private
 * @param {Object} opts The opts to parse.
 * @returns {Object} The ldapjs opts.
 */
function getLdapClientOpts (opts) {
  const clientOpts = [
    'url',
    'host', 'port', 'secure', 'tlsOptions',
    'socketPath', 'log', 'timeout', 'idleTimeout',
    'reconnect', 'queue', 'queueSize', 'queueTimeout',
    'queueDisable', 'bindDN', 'bindCredentials',
    'maxConnections', 'connectTimeout', 'tlsOptions',
    'strictDN', 'paged'
  ]

  const options = {}
  clientOpts.forEach((opt) => {
    if (opts.hasOwnProperty(opt)) {
      options[opt] = opts[opt]
    }
  })

  return options
}

/**
 * Gets the required ldap attributes for group related queries in order to
 * do recursive queries, etc.
 *
 * @private
 * @params {Object} [opts] Optional LDAP query string parameters to execute.
 */
function getRequiredLdapAttributesForGroup (opts) {
  const _opts = opts || {}
  if (shouldIncludeAllAttributes(_opts.attributes)) {
    return []
  }

  return [].concat(
    [ 'dn', 'objectCategory', 'groupType', 'cn' ],
    includeGroupMembershipFor(_opts, 'group') ? ['member'] : []
  )
}

/**
 * Gets the required ldap attributes for user related queries in order to
 * do recursive queries, etc.
 *
 * @private
 * @params {Object} [opts] Optional LDAP query string parameters to execute.
 */
function getRequiredLdapAttributesForUser (opts) {
  const _opts = opts || {}
  if (shouldIncludeAllAttributes(_opts.attributes)) {
    return []
  }

  return [].concat(
    [ 'dn', 'cn' ],
    includeGroupMembershipFor(_opts, 'user') ? [ 'member' ] : []
  )
}

/**
 * Gets the ActiveDirectory LDAP query string for a user search.
 *
 * @private
 * @param {string} username The samAccountName or userPrincipalName
 * (email) of the user.
 * @returns {string}
 */
function getUserQueryFilter (username) {
  if (!username) {
    return '(objectCategory=User)'
  }
  if (isDistinguishedName(username)) {
    return '(&(objectCategory=User)(distinguishedName=' +
      parseDistinguishedName(username) +
      '))'
  }

  return '(&(objectCategory=User)(|(sAMAccountName=' +
    username +
    ')(userPrincipalName=' +
    username +
    ')))'
}

/**
 * Checks to see if group membership for the specified type is enabled.
 *
 * @private
 * @param {object} opts The options to inspect.
 * @param {string} name The name of the membership value to inspect. Values: (all|user|group)
 * @returns {boolean} True if the specified membership is enabled.
 */
function includeGroupMembershipFor (opts, name) {
  const lowerCaseName = name.toLowerCase()
  return (opts.includeMembership || []).some((i) => {
    const j = i.toLowerCase()
    return j === 'all' || j === lowerCaseName
  })
}

/**
 * Checks to see if the value is a distinguished name.
 *
 * @private
 * @param {string} value The value to check to see if it's a distinguished name.
 * @returns {boolean}
 */
function isDistinguishedName (value) {
  if (!value || value.length === 0) {
    return false
  }
  const regex = /(([^=]+=.+),?)+/gi
  return regex.test(value)
}

/**
 * Checks to see if the LDAP result describes a group entry.
 *
 * @private
 * @param {object} item The LDAP result to inspect.
 * @returns {boolean}
 */
function isGroupResult (item) {
  const regex = /CN=Group,CN=Schema,CN=Configuration,.*/i

  if (!item) {
    return false
  }
  if (item.groupType) {
    return true
  }
  if (item.objectCategory) {
    return regex.test(item.objectCategory)
  }
  if (item.objectClass && item.objectClass.length > 0) {
    return item.objectClass.some(c => c.toLowerCase() === 'group')
  }

  return false
}

/**
 * Checks to see if the LDAP result describes a user entry.
 *
 * @private
 * @param {object} item The LDAP result to inspect.
 * @returns {boolean}
 */
function isUserResult (item) {
  const regex = /CN=Person,CN=Schema,CN=Configuration,.*/i

  if (!item) {
    return false
  }
  if (item.userPrincipalName) {
    return true
  }
  if (item.objectCategory) {
    return regex.test(item.objectCategory)
  }
  if (item.objectClass && item.objectClass.length > 0) {
    return item.objectClass.some(c => c.toLowerCase() === 'user')
  }

  return false
}

/**
 * Retrieves / merges the attributes for the query.
 * @private
 * @return {array} An array of attributes
 */
function joinAttributes () {
  for (let arg of Array.from(arguments)) {
    if (shouldIncludeAllAttributes(arg)) {
      return []
    }
  }
  const attrs = []
  Array.from(arguments).forEach((arr) => {
    arr.forEach(i => attrs.push(i))
  })
  return attrs.filter((ele, i, arr) => arr.indexOf(ele) === i)
}

/**
 * Parses the distinguishedName (dn) to remove any invalid characters or to
 * properly escape the request.
 *
 * @private
 * @param {string} dn The dn to parse.
 * @returns {string}
 */
function parseDistinguishedName (dn) {
  if (!dn || Array.isArray(dn)) {
    return dn
  }

  const _dn = dn.replace(/"/g, '\\"')
  return _dn.replace('\\,', '\\\\,')
}

/**
 * Picks only the requested attributes from the ldap result. If a wildcard or
 * empty result is specified, then all attributes are returned.
 * @private
 * @params {object} result The LDAP result.
 * @params {array} attributes The desired or wanted attributes.
 * @returns {object} A copy of the object with only the requested attributes.
 */
function pickAttributes (result, attributes) {
  let _attributes = attributes
  if (shouldIncludeAllAttributes(attributes)) {
    _attributes = Object.getOwnPropertyNames(result)
  }
  const obj = {}
  _attributes.forEach((attr) => {
    if (result.hasOwnProperty(attr)) {
      obj[attr] = result[attr]
    }
  })
  return obj
}

/**
 * Checks to see if any of the specified attributes are the wildcard
 * '*' attribute or if the attributes array is empty.
 * @private
 * @params {array} attributes The attributes to inspect.
 * @returns {boolean}
 */
function shouldIncludeAllAttributes (attributes) {
  if (!Array.isArray(attributes)) {
    return false
  }

  return (attributes.length === 0)
    ? true
    : attributes.filter(a => a === '*').length > 0
}

const maxOutputLength = 256
/**
 * Truncates the specified output to the specified length if exceeded.
 *
 * @private
 * @param {string} output The output to truncate if too long
 * @param {number} [maxLength] The maximum length. If not specified, then the
 * global value maxOutputLength is used.
 */
function truncateLogOutput (output, maxLength) {
  const _maxLength = maxLength || maxOutputLength
  if (!output) {
    return output
  }

  let _output = output
  if (typeof output !== 'string') {
    _output = output.toString()
  }
  const length = _output.length
  if (length < (_maxLength + 3)) {
    return _output
  }

  const prefix = Math.ceil((_maxLength - 3) / 2)
  const suffix = Math.floor((_maxLength - 3) / 2)
  return _output.slice(0, prefix) + '...' + _output.slice(length - suffix)
}

module.exports = {
  createClient,
  getCompoundFilter,
  getGroupQueryFilter,
  getLdapClientOpts,
  getRequiredLdapAttributesForGroup,
  getRequiredLdapAttributesForUser,
  getUserQueryFilter,
  includeGroupMembershipFor,
  isDistinguishedName,
  isGroupResult,
  isUserResult,
  joinAttributes,
  parseDistinguishedName,
  pickAttributes,
  shouldIncludeAllAttributes,
  truncateLogOutput
}
