'use strict'

const events = require('events')
const util = require('util')
const ldap = require('ldapjs')
const async = require('async')
const merge = require('merge-options')

const Group = require('./models/group')
const utils = require('./components/utilities')
const searcher = require('./components/search')
let search = null

const isPasswordLoggingEnabled = false

let log = require('abstract-logging')

const defaultPageSize = 1000 // The maximum number of results that AD will return in a single call. Default=1000

/**
 * Determines which attributes are returned for LDAP queries for each type
 * of LDAP object.
 *
 * Default `user` attributes:
 * + cn
 * + comment
 * + description
 * + displayName
 * + distinquishedName
 * + dn
 * + employeeID
 * + givenName
 * + initials
 * + lockoutTime
 * + mail
 * + pwdLastSet
 * + sAMAccountName
 * + sn
 * + userAccountControl
 * + userPrincipalName
 * + whenCreated
 *
 * Default `group` attributes:
 * + cn
 * + description
 * + distinguishedName
 * + dn
 * + objectCategory
 *
 * @property {array} [user]
 * @property {array} [group]
 * @typedef {object} DefaultAttributes
 */
let defaultAttributes, originalDefaultAttributes
defaultAttributes = originalDefaultAttributes = {
  user: [
    'dn', 'distinguishedName',
    'userPrincipalName', 'sAMAccountName', /* 'objectSID', */ 'mail',
    'lockoutTime', 'whenCreated', 'pwdLastSet', 'userAccountControl',
    'employeeID', 'sn', 'givenName', 'initials', 'cn', 'displayName',
    'comment', 'description'
  ],
  group: [
    'dn', 'cn', 'description', 'distinguishedName', 'objectCategory'
  ]
}

/**
 * @property {boolean} [enabled] Whether or not to chase referrals.
 *                               Default: false.
 * @property {array} [exclude] An array of regular expressions to match for
 *                            referral exclusion even when enabled.
 * @typedef {object} DefaultReferrals
 */
let defaultReferrals, originalDefaultReferrals
defaultReferrals = originalDefaultReferrals = {
  enabled: false,
  // Active directory returns the following partitions as default referrals which we don't want to follow
  exclude: [
    'ldaps?://ForestDnsZones\\..*/.*',
    'ldaps?://DomainDnsZones\\..*/.*',
    'ldaps?://.*/CN=Configuration,.*'
  ]
}

/**
 * Base configuration object for {@link ActiveDirectory}.
 *
 * @example
 * {
 *    url: 'ldap://domain.com',
 *    baseDN: 'dc=domain,dc=com',
 *    username: 'admin@domain.com',
 *    password: 'supersecret',
 *    pageSize: 1000,
 *    referrals: {
 *      enabled: true
 *    },
 *    attributes: {
 *      user: ['sAMAccountName', 'givenName', 'sn', 'mail'],
 *      group: ['cn', 'description', 'dn']
 *    }
 *  }
 *
 * @property {string} url Full LDAP URL to the target Active Directory server.
 * @property {string} baseDN The root DN for all operations.
 * @property {string} username Any Active Directory acceptible username:
 *                            'user', 'user@domain.com', 'domain\user',
 *                            'cn=user,ou=users,dc=root'.
 * @property {string} password The password for the given `username`.
 * @property {int} [pageSize] The default size for paged query results. The
 * default is set to Active Directory's default: 1000.
 * @property {EntryParser} [entryParser]
 * @property {DefaultReferrals} [referrals]
 * @property {DefaultAttributes} [attributes]
 * @typedef {object} ADOptions
 */

/**
 * Allows for a custom function to be specified for parsing of the resulting
 * LDAP object. Examples include augmenting LDAP data with external data from an
 * RDBMs. If `null` is returned, the result is excluded.
 *
 * @example
 * function(entry, raw, callback) {
 *   // returning null to exclude result
 *   if (entry.ignore) return(null);
 *
 *   entry.retrievedAt = new Date();
 *   entry.preferredServer = getPreferredServerFromDatabase(entry.userPrincipalName);
 *
 *   callback(entry);
 * }
 * @typedef {function} EntryParser
 */

const defaultEntryParser = function (entry, raw, callback) {
  if (Object.prototype.hasOwnProperty.call(raw, 'objectSid')) {
    entry.objectSid = utils.binarySidToStringSid(raw.objectSid)
  }
  if (Object.prototype.hasOwnProperty.call(raw, 'objectGUID')) {
    entry.objectGUID = utils.binarySidToStringSid(raw.objectGUID)
  }
  callback(entry)
}

/**
 * When supplying multiple arguments to the {@link ActiveDirectory} constructor,
 * the `defaults` parameter can be used to override some confiuration
 * properties.
 *
 * @property {DefaultAttributes} [attributes]
 * @property {DefaultReferrals} [referrals]
 * @property {EntryParser} [entryParser]
 * @typedef {object} DefaultsParam
 */

/**
 * Agent for retrieving ActiveDirectory user & group information.
 *
 * @public
 * @constructor
 * @param {ADOptions|string} options A full {@link ADOptions} object or
 * a string URL pointing to the remote Active Directory server
 * (e.g. ldap://domain.com). If an object is supplied, all other parameters
 * will be ignored.
 * @param {string} [baseDN] The default base container where all LDAP queries
 * originate from. (i.e. dc=domain,dc=com)
 * @param {string} [username] The administrative username or dn of the user for
 * retrieving user & group information.
 * i.e. Must be a DN or a userPrincipalName (email)
 * @param {string} [password] The administrative password of the specified user.
 * @param {DefaultsParam} [defaults] .
 *
 * @returns {ActiveDirectory}
 */
function ActiveDirectory (options) {
  if (!(this instanceof ActiveDirectory)) {
    // Guard against missing `new` keyword since we don't know if the
    // user is in a strict environment or not.
    const inst = Object.create(ActiveDirectory.prototype)
    ActiveDirectory.apply(inst, arguments)
    return inst
  }

  if (arguments.length === 0) {
    return this
  }

  if ((typeof options) === 'string') {
    const _opts = {
      url: options,
      baseDN: arguments[1],
      username: arguments[2],
      password: arguments[3],
      defaults: arguments[4] || null
    }
    return new ActiveDirectory(_opts)
  }

  const defaultOptions = {
    url: '',
    baseDN: '',
    bindDN: options.username || '',
    bindCredentials: options.password || '',
    referrals: defaultReferrals,
    attributes: defaultAttributes,
    pageSize: options.pageSize || defaultPageSize,
    defaults: {},
    opts: {
      url: '',
      bindDN: '',
      bindCredentials: '',
      entryParser: defaultEntryParser
    }
  }

  const ldapOptions = utils.getLdapClientOpts(options)
  const customEntryParser = options.entryParser ? { entryParser: options.entryParser } : {}
  ldapOptions.bindDN = ldapOptions.bindDN || options.username
  ldapOptions.bindCredentials = ldapOptions.bindCredentials || options.password
  const _options = merge({}, defaultOptions, options)
  Object.defineProperties(this, {
    opts: {
      value: merge({}, defaultOptions.opts, ldapOptions, customEntryParser)
    },
    baseDN: { value: _options.baseDN },
    pageSize: { value: _options.pageSize },
    defaultAttributes: {
      value: merge(
        {}, originalDefaultAttributes, options.attributes,
        (_options.defaults) ? _options.defaults.attributes : {}
      )
    },
    defaultReferrals: {
      value: merge(
        {}, originalDefaultReferrals, _options.referrals,
        (_options.defaults) ? _options.defaults.referrals : {}
      )
    }
  })

  log = _options.logging || log

  defaultAttributes = this.defaultAttributes
  defaultReferrals = this.defaultReferrals

  log.trace('Using username/password (%s/%s) to bind to ActiveDirectory (%s).', this.opts.bindDN,
    isPasswordLoggingEnabled ? this.opts.bindCredentials : '********', this.opts.url)
  log.trace('Referrals are %s', defaultReferrals.enabled
    ? 'enabled. Exclusions: ' + JSON.stringify(defaultReferrals.exclude)
    : 'disabled'
  )
  log.trace('Default user attributes: %j', defaultAttributes.user || [])
  log.trace('Default group attributes: %j', defaultAttributes.group || [])

  events.EventEmitter.call(this)
  search = searcher(this, log)
}
util.inherits(ActiveDirectory, events.EventEmitter)

/**
 * Expose ldapjs filters to avoid TypeErrors for filters
 * @static
 */
ActiveDirectory.filters = ldap.filters

/**
 * Only emits an event if there are any listeners listening.
 *
 * @param {string} event The type of event to emit.
 * @param {*} data The data to send with the emission.
 * @override
 */
ActiveDirectory.prototype.emit = function emit (event, data) {
  if (this.listenerCount(event) > 0) {
    events.EventEmitter.prototype.emit.call(this, event, data)
  }
}

/**
 * Gets all of the groups that the specified distinguishedName (DN) belongs to.
 *
 * @private
 * @param {LDAPQueryParameters} [opts] Optional LDAP query string parameters
 * to execute.
 * @param {string} dn The distinguishedName (DN) to find membership of.
 * @param {function} callback The callback to execute when completed.
 */
ActiveDirectory.prototype.getGroupMembershipForDN = function ggmfd (opts, dn, stack, callback) {
  const getter = require('./components/getGroupMembershipForDN')(this, log)
  return getter(opts, dn, stack, callback)
}

/**
 * For the specified filter, return the distinguishedName (dn) of all the
 * matched entries.
 *
 * @private
 * @param {LDAPQueryParameters} [opts] Optional LDAP query string parameters
 * to execute.
 * @params {(object|string)} filter The LDAP filter to execute. Optionally a
 * custom LDAP query object can be specified.
 * @param {function} callback The callback to execute when completed.
 */
ActiveDirectory.prototype.getDistinguishedNames = function gdns (opts, filter, callback) {
  let _opts = opts || {}
  let _filter = filter
  let _cb = callback

  if (typeof filter === 'function') {
    _cb = filter
    _filter = opts
    _opts = {}
  }
  if (typeof opts === 'string') {
    _filter = opts
    _opts = {}
  }
  log.trace('getDistinguishedNames(%j,%j)', _opts, _filter)

  _opts = merge({},
    {
      filter: _filter,
      scope: 'sub',
      attributes: utils.joinAttributes(_opts.attributes || [], ['dn'])
    },
    _opts
  )
  search(_opts, (err, results) => {
    if (err) {
      return _cb(err)
    }

    const dns = results.map(result => result.dn)
    log.trace(
      '%d distinguishedName(s) found for LDAP query: "%s". Results: %j',
      results.length, utils.truncateLogOutput(_opts.filter), results
    )
    _cb(null, dns)
  })
}

/**
 * Gets the distinguished name for the specified user
 * (userPrincipalName/email or sAMAccountName).
 *
 * @private
 * @param {LDAPQueryParameters} [opts] Optional LDAP query string parameters
 * to execute.
 * @param {String} username The name of the username to retrieve the
 * distinguishedName (dn).
 * @param {function} callback The callback to execute when completed.
 */
ActiveDirectory.prototype.getUserDistinguishedName = function gudn (opts, username, callback) {
  let _opts = opts || {}
  let _username = username
  let _cb = callback

  if (typeof username === 'function') {
    _cb = username
    _username = opts
    _opts = {}
  }
  _opts = merge({}, _opts)
  log.trace('getDistinguishedName(%j,%s)', _opts, _username)

  if (utils.isDistinguishedName(_username)) {
    log.trace('"%s" is already a distinguishedName. NOT performing query.', _username)
    return _cb(null, _username)
  }

  this.getDistinguishedNames(_opts, utils.getUserQueryFilter(_username), (err, dns) => {
    if (err) {
      return _cb(err)
    }

    log.trace('%d distinguishedName(s) found for user: "%s". Returning first dn: "%s"',
      dns.length, _username, dns[0])
    _cb(null, dns[0])
  })
}

/**
 * Gets the distinguished name for the specified group (cn).
 *
 * @private
 * @param {LDAPQueryParameters} [opts] Optional LDAP query string parameters
 * to execute.
 * @param {string} groupName The name of the group to retrieve the
 * distinguishedName (dn).
 * @param {function} callback The callback to execute when completed.
 */
ActiveDirectory.prototype.getGroupDistinguishedName = function ggdn (opts, groupName, callback) {
  let _opts = opts || {}
  let _groupName = groupName
  let _cb = callback

  if (typeof groupName === 'function') {
    _cb = groupName
    _groupName = opts
    _opts = {}
  }
  _opts = merge({}, _opts)
  log.trace('getGroupDistinguishedName(%j,%s)', _opts, _groupName)

  if (utils.isDistinguishedName(_groupName)) {
    log.trace('"%s" is already a distinguishedName. Skipping query.', _groupName)
    return _cb(null, _groupName)
  }

  this.getDistinguishedNames(_opts, utils.getGroupQueryFilter(_groupName), (err, dns) => {
    if (err) {
      return _cb(err)
    }

    log.trace('%d distinguishedName(s) found for group "%s". Returning first dn: "%s"',
      dns.length, _groupName, dns[0])
    _cb(null, dns[0])
  })
}

/**
 * For the specified group, retrieve all of the users that belong to the group.
 *
 * @public
 * @param {LDAPQueryParameters} [opts] Optional LDAP query string parameters
 * to execute.
 * @param {string} groupName The name of the group to retrieve membership from.
 * @param {function} callback The callback to execute when completed.
 */
ActiveDirectory.prototype.getUsersForGroup = function getUsersForGroup (opts, groupName, callback) {
  const searcher = require('./components/getUsersForGroup')(this, log)
  return searcher(opts, groupName, callback)
}

/**
 * For the specified username, get all of the groups that the user is a
 * member of.
 *
 * @public
 * @param {LDAPQueryParameters} [opts] Optional LDAP query string parameters
 * to execute.
 * @param {string} username The username to retrieve membership
 * information about.
 * @param {function} callback The callback to execute when completed.
 */
ActiveDirectory.prototype.getGroupMembershipForUser = function getGroupMembershipForUser (opts, username, callback) {
  const results = []
  let _opts = opts
  let _username = username
  let _cb = callback

  if (typeof username === 'function') {
    _cb = username
    _username = opts
    _opts = {}
  }
  _opts = merge({}, _opts || {})
  log.trace('getGroupMembershipForUser(%j,%s)', _opts, _username)

  const groupDnCallback = (err, groups) => {
    if (err) {
      return _cb(err, results)
    }

    groups.forEach((g) => {
      const result = new Group(
        utils.pickAttributes(g, _opts.attributes || this.defaultAttributes.group)
      )
      this.emit('group', result)
      results.push(result)
    })

    if (_cb) {
      _cb(err, results)
    }
  }

  this.getUserDistinguishedName(_opts, _username, (err, dn) => {
    if (err) {
      return _cb(err, results)
    }

    if (!dn) {
      log.trace('Could not find a distinguishedName for the specified username: "%s"', _username)
      return _cb(err, results)
    }
    this.getGroupMembershipForDN(_opts, dn, groupDnCallback)
  })
}

/**
 * For the specified group, get all of the groups that the group is a member of.
 *
 * @public
 * @param {LDAPQueryParameters} [opts] Optional LDAP query string parameters
 * to execute.
 * @param {string} groupName The group to retrieve membership information about.
 * @param {function} callback The callback to execute when completed.
 */
ActiveDirectory.prototype.getGroupMembershipForGroup = function getGroupMembershipForGroup (opts, groupName, callback) {
  let _opts = opts || {}
  let _groupName = groupName
  let _cb = callback

  if (typeof groupName === 'function') {
    _cb = groupName
    _groupName = opts
    _opts = {}
  }
  _opts = merge({}, _opts)
  log.trace('getGroupMembershipForGroup(%j,%s)', _opts, _groupName)

  this.getGroupDistinguishedName(_opts, _groupName, (err, dn) => {
    if (err) {
      return _cb(err)
    }

    if (!dn) {
      log.trace('Could not find a distinguishedName for the specified group name: "%s"', _groupName)
      return _cb()
    }

    this.getGroupMembershipForDN(_opts, dn, (err, groups) => {
      if (err) {
        return _cb(err)
      }

      const results = []
      groups.forEach((g) => {
        const group = new Group(
          utils.pickAttributes(g, _opts.attributes || this.defaultAttributes.group)
        )
        this.emit('group', group)
        results.push(group)
      })
      _cb(err, results)
    })
  })
}

/**
 * Checks to see if the specified username exists.
 *
 * @param {LDAPQueryParameters} [opts] Optional LDAP query string parameters to
 * execute.
 * @param {string} username The username to check to see if it exits.
 * @param {function} callback The callback to execute when completed.
 */
ActiveDirectory.prototype.userExists = function userExists (opts, username, callback) {
  let _opts = opts
  let _username = username
  let _cb = callback

  if (typeof username === 'function') {
    _cb = username
    _username = opts
    _opts = null
  }
  _opts = merge({}, _opts || {})
  log.trace('userExists(%j,%s)', _opts, _username)

  this.findUser(_opts, _username, function (err, user) {
    if (err) {
      return _cb(err)
    }

    log.trace('"%s" %s exist.', _username, (user != null) ? 'DOES' : 'DOES NOT')
    _cb(null, user != null)
  })
}

/**
 * Checks to see if the specified group exists.
 *
 * @param {LDAPQueryParameters} [opts] Optional LDAP query string parameters to
 * execute.
 * @param {string} groupName The group to check to see if it exists.
 * @param {function} callback The callback to execute when completed.
 */
ActiveDirectory.prototype.groupExists = function groupExists (opts, groupName, callback) {
  let _opts = opts
  let _groupName = groupName
  let _cb = callback

  if (typeof groupName === 'function') {
    _cb = groupName
    _groupName = opts
    _opts = null
  }
  _opts = merge({}, _opts)
  log.trace('groupExists(%j,%s)', _opts, _groupName)

  this.findGroup(_opts, _groupName, function (err, result) {
    if (err) {
      return _cb(err)
    }

    log.trace('"%s" %s exist.', _groupName, (result != null) ? 'DOES' : 'DOES NOT')
    _cb(null, result != null)
  })
}

/**
 * Checks to see if the specified user is a member of the specified group.
 *
 * @param {LDAPQueryParameters} [opts] Optional LDAP query string parameters to
 * execute.
 * @param {string} username The username to check for membership.
 * @param {string} groupName The group to check for membership.
 * @param {function} callback The callback to execute when completed.
 */
ActiveDirectory.prototype.isUserMemberOf = function isUserMemberOf (opts, username, groupName, callback) {
  let _opts = opts
  let _username = username
  let _groupName = groupName
  let _cb = callback

  if (typeof groupName === 'function') {
    _cb = groupName
    _groupName = username
    _username = opts
    _opts = {}
  }
  _opts = merge({}, _opts)
  log.trace('isUserMemberOf(%j,%s,%s)', _opts, _username, _groupName)

  _opts.attributes = ['cn', 'dn']
  this.getGroupMembershipForUser(_opts, _username, function (err, groups) {
    if (err) {
      return _cb(err)
    }
    if (groups.length === 0) {
      log.trace('"%s" IS NOT a member of "%s". No groups found for user.', _username, _groupName)
      return _cb(null, false)
    }

    // Check to see if the group.distinguishedName or group.cn matches the list of
    // retrieved groups.
    const lowerCaseGroupName = _groupName.toLowerCase().replace(/\s/g, '')
    const result = groups.filter((g) => g.dn.toLowerCase().replace(/\s/g, '') === lowerCaseGroupName || g.cn.toLowerCase().replace(/\s/g, '').includes(lowerCaseGroupName)).length > 0
    log.trace('"%s" %s a member of "%s"', _username, result ? 'IS' : 'IS NOT', _groupName)
    _cb(null, result)
  })
}

/**
 * Perform a generic search for the specified LDAP query filter. This function
 * will return both groups and users that match the specified filter. Any
 * results not recognized as a user or group (i.e. computer accounts, etc.) can
 * be found in the 'other' property of the result.
 *
 * @example <caption>result object</caption>
 * {
 *   users: [],
 *   groups: [],
 *   other: []
 * }
 *
 * @public
 * @param {(LDAPQueryParameters|string)} [opts] Optional LDAP query string
 * parameters to execute. Optionally, if only a string is provided, then the
 * string is assumed to be an LDAP filter.
 * @param {function} callback The callback to execute when completed.
 */
ActiveDirectory.prototype.find = function find (opts, callback) {
  const finder = require('./components/find')(this, log)
  finder(opts, callback)
}

/**
 * Perform a generic search on the Deleted Objects container for
 * Active Directory. For this method to work correctly, the tombstone feature
 * for active directory must be enabled. A tombstoned object has most of the
 * attributes stripped from the object.
 *
 * @public
 * @param {LDAPQueryParameters} [opts] Optional LDAP query string parameters
 * to execute. Optionally, if only a string is provided, then the string is
 * assumed to be an LDAP filter.
 * @param {function} callback The callback to execute when completed.
 */
ActiveDirectory.prototype.findDeletedObjects = function find (opts, callback) {
  let _opts = opts || {}
  let _cb = callback

  if (typeof opts === 'function') {
    _cb = opts
    _opts = {}
  }
  if (typeof opts === 'string') {
    _opts = { filter: opts }
  }
  _opts = merge({}, _opts)
  log.trace('findDeletedObjects(%j)', _opts)

  const defaultDeletedAttributes = [
    'attributeID', 'attributeSyntax', 'dnReferenceUpdate', 'dNSHostName', 'flatName',
    'governsID', 'groupType', 'instanceType', 'lDAPDisplayName', 'legacyExchangeDN',
    'mS-DS-CreatorSID', 'mSMQOwnerID', 'nCName', 'objectClass', 'objectGUID', 'objectSid',
    'oMSyntax', 'proxiedObjectName', 'replPropertyMetaData', 'sAMAccountName', 'securityIdentifier',
    'sIDHistory', 'subClassOf', 'systemFlags', 'trustPartner', 'trustDirection', 'trustType',
    'trustAttributes', 'userAccountControl', 'uSNChanged', 'uSNCreated', 'whenCreated',
    'msDS-AdditionalSam­AccountName', 'msDS-Auxiliary-Classes', 'msDS-Entry-Time-To-Die',
    'msDS-IntId', 'msSFU30NisDomain', 'nTSecurityDescriptor', 'uid'
  ]
  const localOpts = merge({},
    {
      scope: 'one',
      attributes: utils.joinAttributes(_opts.attributes || [], defaultDeletedAttributes),
      controls: []
    },
    _opts
  )

  const searchDeletedObjects = (baseDN, options) => {
    const innerOpts = merge({}, options, { includeDeleted: true })
    search(baseDN, innerOpts, (err, results) => {
      if (err) {
        return _cb(err)
      }

      if (results.length === 0) {
        log.trace('No deleted objects found for query "%s"', utils.truncateLogOutput(_opts.filter))
        this.emit('done', null)
        return _cb()
      }

      const deletedItems = []
      async.forEach(
        results,

        (result, acb) => {
          const deletedItem = utils.pickAttributes(result, _opts.attributes || {})
          this.emit('entry:deleted', deletedItem)
          deletedItems.push(deletedItem)
        },

        (err) => {
          log.trace(
            '%d deleted objects found for query "%s". Results: %j',
            deletedItems.length, utils.truncateLogOutput(localOpts.filter), deletedItems
          )
          this.emit('deleted', deletedItems)
          _cb(err, deletedItems)
        }
      )
    })
  }

  if (!localOpts.baseDN) {
    log.trace('No baseDN specified for Deleted Object. Querying RootDSE at %s.', this.opts.url)
    this.getRootDSE(this.opts.url, ['defaultNamingContext'], (err, result) => {
      if (err) {
        return _cb(err)
      }

      log.trace('Retrieved defaultNamingContext (%s) from RootDSE at %s.', result.defaultNamingContext, this.opts.url)
      searchDeletedObjects('CN=Deleted Objects,' + result.defaultNamingContext, localOpts)
    })
  } else {
    searchDeletedObjects(localOpts.baseDN, localOpts)
  }
}

/**
 * Retrieves the specified group.
 *
 * @public
 * @param {LDAPQueryParameters} [opts] Optional LDAP query string parameters
 * to execute.
 * @param {string} groupName The group (cn) to retrieve information about.
 * Optionally can pass in the distinguishedName (dn) of the group to retrieve.
 * @param {function} callback The callback to execute when completed.
 */
ActiveDirectory.prototype.findGroup = function findGroup (opts, groupName, callback) {
  let _opts = opts || {}
  let _groupName = groupName
  let _cb = callback

  if (typeof groupName === 'function') {
    _cb = groupName
    _groupName = opts
    _opts = {}
  }
  if (typeof opts === 'string') {
    _groupName = opts
    _opts = {}
  }
  _opts = merge({}, _opts)
  _opts.filter = (_opts.filter)
    ? _opts.filter
    : utils.getGroupQueryFilter(_groupName)
  log.trace('findGroup(%j,%s)', _opts, _groupName)

  const finder = require('./components/findGroups')(this, log)
  finder(_opts, (err, groups) => {
    if (err) {
      return _cb(err)
    }

    if (groups && groups.length > 0) {
      return _cb(null, groups[0])
    }

    return _cb()
  })
}

/**
 * Perform a generic search for groups that match the specified filter.
 * The default LDAP filter for groups is specified as
 * `(&(objectClass=group)(!(objectClass=computer))(!(objectClass=user))(!(objectClass=person)))`.
 *
 * @public
 * @param {LDAPQueryParameters} [opts] Optional LDAP query string parameters
 * to execute. Optionally, if only a string is provided, then the string is
 * assumed to be an LDAP filter that will be appended as the last parameter
 * in the default LDAP filter.
 * @param {function} callback The callback to execute when completed.
 */
ActiveDirectory.prototype.findGroups = function findGroup (opts, callback) {
  const finder = require('./components/findGroups')(this, log)
  return finder(opts, callback)
}

/**
 * Retrieves the specified user.
 *
 * @public
 * @param {LDAPQueryParameters} [opts] Optional LDAP query string parameters
 * to execute.
 * @param {string} username The username to retrieve information about.
 * Optionally can pass in the distinguishedName (dn) of the user to retrieve.
 * @param {boolean} [includeMembership] OBSOLETE; NOT NOT USE. Indicates if the
 * results should include group memberships for the user. Defaults to `false`.
 * @param {function} callback The callback to execute when completed.
 */
ActiveDirectory.prototype.findUser = function findUser (opts, username, includeMembership, callback) {
  let _opts = opts || {}
  let _username = username
  let _inclMembership = includeMembership
  let _cb = callback

  if (typeof includeMembership === 'function') {
    _cb = includeMembership
    _inclMembership = null
  }
  if (typeof username === 'function') {
    _cb = username
    _username = opts
    _opts = {}
  }
  if (typeof username === 'boolean') {
    _inclMembership = username
    _username = opts
    _opts = {}
  }
  if (typeof opts === 'string') {
    _username = opts
    _opts = {}
  }
  _opts = merge({}, _opts)
  _opts.filter = (_opts.filter)
    ? _opts.filter
    : utils.getUserQueryFilter(_username)
  log.trace('findUser(%j,%s,%s)', _opts, _username, _inclMembership)

  const finder = require('./components/findUsers')(this, log)
  let isErrInvoked = false
  return finder(_opts, _inclMembership, (err, users) => {
    if (err && !isErrInvoked) {
      // For some unknown reason, the onClientError function in #search is
      // getting invoked twice during the ctor#InvalidCredentialsError
      // test. This hacks around the issue.
      isErrInvoked = true
      return _cb(err)
    }

    if (users && users.length > 0) {
      return _cb(null, users[0])
    }

    return _cb()
  })
}

/**
 * Perform a generic search for users that match the specified filter. The
 * default LDAP filter for users is specified as
 * `(&(|(objectClass=user)(objectClass=person))(!(objectClass=computer))(!(objectClass=group)))`.
 *
 * @public
 * @param {(LDAPQueryParameters|string)} [opts] Optional LDAP query string
 * parameters to execute. Optionally, if only a string is provided, then the
 * string is assumed to be an LDAP filter that will be appended as the last
 * parameter in the default LDAP filter.
 * @param {boolean} [includeMembership] OBSOLETE; NOT NOT USE. Indicates if the
 * results should include group memberships for the user. Defaults to `false`.
 * @param {function} callback The callback to execute when completed.
 */
ActiveDirectory.prototype.findUsers = function findUsers (opts, includeMembership, callback) {
  const finder = require('./components/findUsers')(this, log)
  return finder(opts, includeMembership, callback)
}

/**
 * Authenticates the username and password by doing a simple bind with the
 * specified credentials.
 *
 * @public
 * @param {string} username The username to authenticate.
 * @param {string} password The password to use for authentication.
 * @param {function} callback The callback to execute when the authenication is
 * completed. The callback is a standard Node style callback with `error` and
 * `result` parameters. The `result` parameter will always be either `true` or
 * `false`.
 */
ActiveDirectory.prototype.authenticate = function authenticate (username, password, callback) {
  log.trace('authenticate(%j,%s)', username, isPasswordLoggingEnabled ? password : '********')

  // Skip authentication if an empty username or password is provided.
  if ((!username) || (!password)) {
    const err = {
      code: 0x31,
      errno: 'LDAP_INVALID_CREDENTIALS',
      description: 'The supplied credential is invalid'
    }
    return callback(err, false)
  }

  const client = utils.createClient(null, null, this)
  let callbackInvoked = false
  function invokeCallback (err, result) {
    if (callbackInvoked) return
    callbackInvoked = true
    callback(err, result)
  }
  client.on('connectTimeout', (err) => {
    this.emit('error', err)
    return invokeCallback(err, false)
  })
  client.on('error', (err) => {
    // only used on socket connection failure since it doesn't invoke bind cb
    this.emit('error', err)
    return invokeCallback(err, false)
  })
  client.bind(username, password, (err) => {
    client.unbind()
    const message = util.format('Authentication %s for "%s" as "%s" (password: "%s")',
      err ? 'failed' : 'succeeded',
      this.opts.url, username, isPasswordLoggingEnabled ? password : '********')
    if (err) {
      log.trace('%s. Error: %s', message, err)
      this.emit('error', err)
      return invokeCallback(err, false)
    }

    log.trace(message)
    return invokeCallback(err, true)
  })
}

/**
 * Retrieves the root DSE for the specified url
 *
 * @public
 * @param {string} url The url to retrieve the root DSE for.
 * @param {array} [attributes] The optional list of attributes to retrieve.
 * Returns all if not specified.
 * @param {function} callback The callback to execute when completed.
 */
ActiveDirectory.prototype.getRootDSE = function getRootDSE (url, attributes, callback) { // jshint -W071
  let _url = url
  let _attributes = attributes
  let _cb = callback

  if (typeof url !== 'string' && this instanceof ActiveDirectory) {
    _url = this.url || this.opts.url
    _cb = url
  }

  if (typeof attributes === 'function') {
    _attributes = null
    _cb = attributes
  }

  _attributes = _attributes || ['*']

  if (!url) {
    throw new Error('Must specify an URL in the form: ldap://example.com:389')
  }
  log.trace('getRootDSE(%s,%j)', _url, _attributes)

  const client = utils.createClient.call(this, _url, this)
  client.on('error', (err) => {
    // only needed for bind errors
    if (err.errno !== 'ECONNRESET') { // we don't care about ECONNRESET
      log.trace('A connection error occured searching for root DSE at %s. Error: %s', _url, err)
      this.emit('error', err)
      _cb(err)
    }
  })
  // Anonymous bind
  client.bind('', '', function (err) {
    if (err) {
      log.trace('Anonymous bind to "%s" failed. Error: %s', url, err)
      return _cb(err)
    }

    client.search('', { scope: 'base', attributes: _attributes, filter: '(objectClass=*)' }, function (err, result) {
      if (err) {
        log.trace('Root DSE search failed for "%s". Error: %s', url, err)
        return _cb(err)
      }

      result.on('end', function () {
        client.unbind()
      })
      result.on('searchEntry', function (entry) {
        const obj = entry.object
        delete obj.controls
        _cb(null, obj)
      })
    })
  })
}

ActiveDirectory.getRootDSE = function staticGetRootDSE (url, attributes, cb) {
  if (typeof url !== 'string') {
    throw new Error('Must specify an URL in the form: ldap://example.com:389')
  }

  if (typeof attributes === 'function') {
    return ActiveDirectory.prototype.getRootDSE(url, null, attributes)
  }

  return ActiveDirectory.prototype.getRootDSE(url, attributes, cb)
}

ActiveDirectory.defaultAttributes = defaultAttributes

module.exports = ActiveDirectory
