var events = require('events');
var util = require('util');
var ldap = require('ldapjs');
var async = require('async');
var _ = require('underscore');
var bunyan = require('bunyan');
var Url = require('url');

var User = require('./models/user');
var Group = require('./models/group');
var RangeRetrievalSpecifierAttribute = require('./client/rangeretrievalspecifierattribute');

var isPasswordLoggingEnabled = false;
var maxOutputLength = 256;

var log = bunyan.createLogger({
  name: 'ActiveDirectory',
  streams: [
    { level: 'fatal',
      stream: process.stdout }
  ]
});

var defaultPageSize = 1000; // The maximum number of results that AD will return in a single call. Default=1000
var defaultAttributes, originalDefaultAttributes;
defaultAttributes = originalDefaultAttributes = {
  user: [ 
    'dn',
    'userPrincipalName', 'sAMAccountName', /*'objectSID',*/ 'mail',
    'lockoutTime', 'whenCreated', 'pwdLastSet', 'userAccountControl',
    'employeeID', 'sn', 'givenName', 'initials', 'cn', 'displayName',
    'comment', 'description' 
  ],
  group: [
    'dn', 'cn', 'description'
  ]
};

var defaultReferrals, originalDefaultReferrals;
defaultReferrals = originalDefaultReferrals = {
  enabled: false,
  // Active directory returns the following partitions as default referrals which we don't want to follow
  exclude: [
    'ldaps?://ForestDnsZones\\..*/.*',
    'ldaps?://DomainDnsZones\\..*/.*',
    'ldaps?://.*/CN=Configuration,.*'
  ]
};

// Precompile some common, frequently used regular expressions.
var re = {
  'isDistinguishedName': /(([^=]+=.+),?)+/gi,
  'isUserResult': /CN=Person,CN=Schema,CN=Configuration,.*/i,
  'isGroupResult': /CN=Group,CN=Schema,CN=Configuration,.*/i
};

/**
 * Agent for retrieving ActiveDirectory user & group information.
 *
 * @public
 * @constructor
 * @param {Object|String} url The url of the ldap server (i.e. ldap://domain.com). Optionally, all of the parameters can be specified as an object. { url: 'ldap://domain.com', baseDN: 'dc=domain,dc=com', username: 'admin@domain.com', password: 'supersecret', { referrals: { enabled: true }, attributes: { user: [ 'attributes to include in response' ], group: [ 'attributes to include in response' ] } } }. 'attributes' & 'referrals' parameter is optional and only necesary if overriding functionality.
 * @param {String} baseDN The default base container where all LDAP queries originate from. (i.e. dc=domain,dc=com)
 * @param {String} username The administrative username or dn of the user for retrieving user & group information. (i.e. Must be a DN or a userPrincipalName (email))
 * @param {String} password The administrative password of the specified user.
 * @param {Object} defaults Allow for default options to be overridden. { attributes: { user: [ 'attributes to include in response' ], group: [ 'attributes to include in response' ] } }
 * @returns {ActiveDirectory}
 */
var ActiveDirectory = function(url, baseDN, username, password, defaults) {
  if (this instanceof ActiveDirectory) {
    this.opts = {};
    if (typeof(url) === 'string') {
      this.opts.url = url;
      this.baseDN = baseDN;
      this.opts.bindDN = username;
      this.opts.bindCredentials = password;

      if (typeof((defaults || {}).entryParser) === 'function') {
        this.opts.entryParser = defaults.entryParser;
      }
    }
    else {
      this.opts = _.defaults({}, url);
      this.baseDN = this.opts.baseDN;

      if (! this.opts.bindDN) this.opts.bindDN = this.opts.username;
      if (! this.opts.bindCredentials) this.opts.bindCredentials = this.opts.password;

      if (this.opts.logging) {
        log = bunyan.createLogger(_.defaults({}, this.opts.logging));
        delete(this.opts.logging);
      }
    }

    defaultAttributes = _.extend({}, originalDefaultAttributes, (this.opts || {}).attributes || {}, (defaults || {}).attributes || {});
    defaultReferrals = _.extend({}, originalDefaultReferrals, (this.opts || {}).referrals || {}, (defaults || {}).referrals  || {});

    log.info('Using username/password (%s/%s) to bind to ActiveDirectory (%s).', this.opts.bindDN,
             isPasswordLoggingEnabled ? this.opts.bindCredentials : '********', this.opts.url);
    log.info('Referrals are %s', defaultReferrals.enabled ? 'enabled. Exclusions: '+JSON.stringify(defaultReferrals.exclude): 'disabled');
    log.info('Default user attributes: %j', defaultAttributes.user || []);
    log.info('Default group attributes: %j', defaultAttributes.group || []);

    // Enable connection pooling
    // TODO: To be disabled / removed in future release of ldapjs > 0.7.1
    if (typeof(this.opts.maxConnections) === 'undefined') {
      this.opts.maxConnections = 20;
    }
    events.EventEmitter.call(this);
  }
  else {
    return(new ActiveDirectory(url, baseDN, username, password, defaults));
  }
};
util.inherits(ActiveDirectory, events.EventEmitter);

/**
 * Expose ldapjs filters to avoid TypeErrors for filters
 * @static
 */
ActiveDirectory.filters = ldap.filters;

/**
 * Truncates the specified output to the specified length if exceeded.
 * @param {String} output The output to truncate if too long
 * @param {Number} [maxLength] The maximum length. If not specified, then the global value maxOutputLength is used.
 */
function truncateLogOutput(output, maxLength) {
  if (typeof(maxLength) === 'undefined') maxLength = maxOutputLength;
  if (! output) return(output);

  if (typeof(output) !== 'string') output = output.toString();
  var length = output.length;
  if ((! length) || (length < (maxLength + 3))) return(output);

  var prefix = Math.ceil((maxLength - 3)/2);
  var suffix = Math.floor((maxLength - 3)/2);
  return(output.slice(0, prefix)+ '...' +
    output.slice(length-suffix));
}

/**
 * Checks to see if there are any event emitters defined for the
 * specified event name.
 * @param {String} event The name of the event to inspect.
 * @returns {Boolean} True if there are events defined, false if otherwise.
 */
function hasEvents(event) {
  return(events.EventEmitter.listenerCount(this, event) > 0);
}

/**
 * Checks to see if the value is a distinguished name.
 *
 * @private
 * @param {String} value The value to check to see if it's a distinguished name.
 * @returns {Boolean}
 */
function isDistinguishedName(value) {
  log.trace('isDistinguishedName(%s)', value);
  if ((! value) || (value.length === 0)) return(false);
  re.isDistinguishedName.lastIndex = 0; // Reset the regular expression
  return(re.isDistinguishedName.test(value));
}

/**
 * Parses the distinguishedName (dn) to remove any invalid characters or to
 * properly escape the request.
 *
 * @private
 *   @param dn {String} The dn to parse.
 * @returns {String}
 */
function parseDistinguishedName(dn) {
  log.trace('parseDistinguishedName(%s)', dn);
  if (! dn) return(dn);

  dn = dn.replace(/"/g, '\\"');
  return(dn.replace('\\,', '\\\\,'));
}

/**
 * Gets the ActiveDirectory LDAP query string for a user search.
 *
 * @private
 * @param {String} username The samAccountName or userPrincipalName (email) of the user.
 * @returns {String}
 */
function getUserQueryFilter(username) {
  log.trace('getUserQueryFilter(%s)', username);
  var self = this;

  if (! username) return('(objectCategory=User)');
  if (isDistinguishedName.call(self, username)) {
    return('(&(objectCategory=User)(distinguishedName='+parseDistinguishedName(username)+'))');
  }

  return('(&(objectCategory=User)(|(sAMAccountName='+username+')(userPrincipalName='+username+')))');
}

/**
 * Gets a properly formatted LDAP compound filter. This is a very simple approach to ensure that the LDAP
 * compound filter is wrapped with an enclosing () if necessary. It does not handle parsing of an existing
 * compound ldap filter.
 * @param {String} filter The LDAP filter to inspect.
 * @returns {String}
 */
function getCompoundFilter(filter) {
  log.trace('getCompoundFilter(%s)', filter);

  if (! filter) return(false);
  if ((filter.charAt(0) === '(') && (filter.charAt(filter.length - 1) === ')')) {
    return(filter);
  }
  return('('+filter+')');
}

/**
 * Gets the ActiveDirectory LDAP query string for a group search.
 *
 * @private
 * @param {String} groupName The name of the group
 * @returns {String}
 */
function getGroupQueryFilter(groupName) {
  log.trace('getGroupQueryFilter(%s)', groupName);
  var self = this;

  if (! groupName) return('(objectCategory=Group)');
  if (isDistinguishedName.call(self, groupName)) {
    return('(&(objectCategory=Group)(distinguishedName='+parseDistinguishedName(groupName)+'))');
  }
  return('(&(objectCategory=Group)(cn='+groupName+'))');
}

/**
 * Checks to see if the LDAP result describes a group entry.
 * @param {Object} item The LDAP result to inspect.
 * @returns {Boolean}
 */
function isGroupResult(item) {
  log.trace('isGroupResult(%j)', item);

  if (! item) return(false);
  if (item.groupType) return(true);
  if (item.objectCategory) {
    re.isGroupResult.lastIndex = 0; // Reset the regular expression
    return(re.isGroupResult.test(item.objectCategory));
  }
  if ((item.objectClass) && (item.objectClass.length > 0)) {
    return(_.any(item.objectClass, function(c) { return(c.toLowerCase() === 'group'); }));
  }
  return(false);
}

/**
 * Checks to see if the LDAP result describes a user entry.
 * @param {Object} item The LDAP result to inspect.
 * @returns {Boolean}
 */
function isUserResult(item) {
  log.trace('isUserResult(%j)', item);

  if (! item) return(false);
  if (item.userPrincipalName) return(true);
  if (item.objectCategory) {
    re.isUserResult.lastIndex = 0; // Reset the regular expression
    return(re.isUserResult.test(item.objectCategory));
  }
  if ((item.objectClass) && (item.objectClass.length > 0)) {
    return(_.any(item.objectClass, function(c) { return(c.toLowerCase() === 'user'); }));
  }
  return(false);
}

/**
 * Factory to create the LDAP client object.
 *
 * @private
 * @param {String} url The url to use when creating the LDAP client.
 * @param {object} opts The optional LDAP client options.
 */
function createClient(url, opts) {
  // Attempt to get Url from this instance.
  url = url || this.url || (this.opts || {}).url || (opts || {}).url;
  if (! url) {
    throw 'No url specified for ActiveDirectory client.';
  }
  log.trace('createClient(%s)', url);

  var opts = getLdapClientOpts(_.defaults({}, { url: url }, opts, this.opts));
  log.debug('Creating ldapjs client for %s. Opts: %j', opts.url, _.omit(opts, 'url', 'bindDN', 'bindCredentials'));
  var client = ldap.createClient(opts);
  return(client);
}

/**
 * Checks to see if the specified referral or "chase" is allowed.
 * @param {String} referral The referral to inspect.
 * @returns {Boolean} True if the referral should be followed, false if otherwise.
 */
function isAllowedReferral(referral) {
  log.trace('isAllowedReferral(%j)', referral);
  if (! defaultReferrals.enabled) return(false);
  if (! referral) return(false);

  return(! _.any(defaultReferrals.exclude, function(exclusion) {
    var re = new RegExp(exclusion, "i");
    return(re.test(referral));
  }));
}

/**
 * From the list of options, retrieves the ldapjs specific options.
 *
 * @param {Object} opts The opts to parse.
 * @returns {Object} The ldapjs opts.
 */
function getLdapOpts(opts) {
  return(_.defaults({}, getLdapClientOpts(opts), getLdapSearchOpts(opts)));
}

/**
 * From the list of options, retrieves the ldapjs client specific options.
 *
 * @param {Object} opts The opts to parse.
 * @returns {Object} The ldapjs opts.
 */
function getLdapClientOpts(opts) {
  return(_.pick(opts || {},
    // Client
    'url',
    'host', 'port', 'secure', 'tlsOptions',
    'socketPath', 'log', 'timeout', 'idleTimeout',
    'reconnect', 'queue', 'queueSize', 'queueTimeout',
    'queueDisable', 'bindDN', 'bindCredentials',
    'maxConnections'
  ));
}

/**
 * From the list of options, retrieves the ldapjs search specific options.
 *
 * @param {Object} opts The opts to parse.
 * @returns {Object} The ldapjs opts.
 */
function getLdapSearchOpts(opts) {
  return(_.pick(opts || {},
    // Search
    'filter', 'scope', 'attributes', 'controls',
    'paged', 'sizeLimit', 'timeLimit', 'typesOnly',
    'derefAliases'
  ));
}

/**
 * Performs a search on the LDAP tree.
 * 
 * @private
 * @param {String} [baseDN] The optional base directory where the LDAP query is to originate from. If not specified, then starts at the root.
 * @param {Object} [opts] LDAP query string parameters to execute. { scope: '', filter: '', attributes: [ '', '', ... ], sizeLimit: 0, timelimit: 0 }
 * @param {Function} callback The callback to execure when completed. callback(err: {Object}, results: {Array[Object]}})
 */
function search(baseDN, opts, callback) {
  var self = this;

  if (typeof(opts) === 'function') {
    callback = opts;
    opts = baseDN;
    baseDN = undefined;
  }
  if (typeof(baseDN) === 'object') {
    opts = baseDN;
    baseDN = undefined;
  }
  opts || (opts = {});
  baseDN || (baseDN = opts.baseDN) || (baseDN = self.baseDN);
  log.trace('search(%s,%j)', baseDN, opts);

  var isDone = false;
  var pendingReferrals = [];
  var pendingRangeRetrievals = 0;
  var client = createClient.call(self, null, opts);
  client.on('error', onClientError);

  /**
   * Call to remove the specified referral client.
   * @param {Object} client The referral client to remove.
   */
  function removeReferral(client) {
    if (! client) return;

    client.unbind();
    var indexOf = pendingReferrals.indexOf(client);
    if (indexOf >= 0) {
      pendingReferrals.splice(indexOf, 1);
    }
  }

  /**
   * The default entry parser to use. Does not modifications.
   * @params {Object} entry The original / raw ldapjs entry to augment
   * @params {Function} callback The callback to execute when complete.
   */
  var entryParser = (opts || {}).entryParser || (self.opts || {}).entryParser || function onEntryParser(item, raw, callback) {
    callback(item);
  };

  /**
   * Occurs when a search entry is received. Cleans up the search entry and pushes it to the result set.
   * @param {Object} entry The entry received.
   */
  function onSearchEntry(entry) {
    log.trace('onSearchEntry(%j)', entry);
    var result = entry.object;
    delete result.controls; // Remove the controls array returned as part of the SearchEntry

    // Some attributes can have range attributes (paging). Execute the query
    // again to get additional items.
    pendingRangeRetrievals++;
    parseRangeAttributes.call(self, result, opts, function(err, item) {
      pendingRangeRetrievals--;

      if (err) item = entry.object;
      entryParser(item, entry.raw, function(item) {
        if (item) results.push(item);
        if ((! pendingRangeRetrievals) && (isDone)) {
          onSearchEnd();
        }
      });
    });
  }

  /**
   * Occurs when a search reference / referral is received. Follows the referral chase if
   * enabled.
   * @param {Object} ref The referral.
   */
  function onReferralChase(ref) {
    var index = 0;
    var referralUrl;
    // Loop over the referrals received.
    while (referralUrl = (ref.uris || [])[index++]) {
      if (isAllowedReferral(referralUrl)) {
        log.debug('Following LDAP referral chase at %s', referralUrl);
        var referralClient = createClient.call(self, referralUrl, opts);
        pendingReferrals.push(referralClient);

        var referral = Url.parse(referralUrl);
        var referralBaseDn = (referral.pathname || '/').substring(1);
        referralClient.search(referralBaseDn, getLdapOpts(opts), controls, function(err, res) {
          /**
           * Occurs when a error is encountered with the referral client.
           * @param {Object} err The error object or string.
           */
          function onReferralError(err) {
            log.error(err, '[%s] An error occurred chasing the LDAP referral on %s (%j)',
                     (err || {}).errno, referralBaseDn, opts);
            removeReferral(referralClient);
          }
          // If the referral chase / search failed, fail silently.
          if (err) {
            onReferralError(err);
            return;
          }

          res.on('searchEntry', onSearchEntry);
          res.on('searchReference', onReferralChase);
          res.on('error', onReferralError);
          res.on('end', function(result) {
            removeReferral(referralClient);
            onSearchEnd();
          });
        });
      }
    }
  }

  /**
   * Occurs when a client / search error occurs.
   * @param {Object} err The error object or string.
   * @param {Object} res The optional server response.
   */
  function onClientError(err, res) {
    if ((err || {}).name === 'SizeLimitExceededError') {
      onSearchEnd(res);
      return;
    }

    client.unbind();
    log.error(err, '[%s] An error occurred performing the requested LDAP search on %s (%j)',
              (err || {}).errno || 'UNKNOWN', baseDN, opts);
    if (callback) callback(err);
  }

  /**
   * Occurs when a search results have all been processed.
   * @param {Object} result
   */
  function onSearchEnd(result) {
    if ((! pendingRangeRetrievals) && (pendingReferrals.length <= 0)) {
      client.unbind();
      log.info('Active directory search (%s) for "%s" returned %d entries.',
               baseDN, truncateLogOutput(opts.filter),
               (results || []).length);
      if (callback) callback(null, results);
    }
  }

  var results = [];
  
  var controls = opts.controls || (opts.controls = []);
  // Add paging results control by default if not already added.
  if (!_.any(controls, function(control) { return(control instanceof ldap.PagedResultsControl); })) {
    log.debug('Adding PagedResultControl to search (%s) with filter "%s" for %j',
              baseDN, truncateLogOutput(opts.filter), _.any(opts.attributes) ? opts.attributes : '[*]');
    controls.push(new ldap.PagedResultsControl({ value: { size: defaultPageSize } }));
  }
  if (opts.includeDeleted) {
    if (!_.any(controls, function(control) { return(control.type === '1.2.840.113556.1.4.417'); })) {
      log.debug('Adding ShowDeletedOidControl(1.2.840.113556.1.4.417) to search (%s) with filter "%s" for %j',
                baseDN, truncateLogOutput(opts.filter), _.any(opts.attributes) ? opts.attributes : '[*]');
      controls.push(new ldap.Control({ type: '1.2.840.113556.1.4.417', criticality: true }));
    }
  }

  log.debug('Querying active directory (%s) with filter "%s" for %j',
            baseDN, truncateLogOutput(opts.filter), _.any(opts.attributes) ? opts.attributes : '[*]');
  client.search(baseDN, getLdapOpts(opts), controls, function onSearch(err, res) {
    if (err) {
      if (callback) callback(err);
      return;
    }

    res.on('searchEntry', onSearchEntry);
    res.on('searchReference', onReferralChase);
    res.on('error', function(err) { onClientError(err, res); });
    res.on('end', function(result) {
      isDone = true; // Flag that the primary query is complete
      onSearchEnd(result);
    });
  });
}

/**
 * Handles any attributes that might have been returned with a range= specifier.
 *
 * @private
 * @param {Object} result The entry returned from the query.
 * @param {Object} opts The original LDAP query string parameters to execute. { scope: '', filter: '', attributes: [ '', '', ... ], sizeLimit: 0, timelimit: 0 }
 * @param {Function} callback The callback to execute when completed. callback(err: {Object}, result: {Object}})
 */
function parseRangeAttributes(result, opts, callback) {
  log.trace('parseRangeAttributes(%j,%j)', result, opts);
  var self = this;

  // Check to see if any of the result attributes have range= attributes.
  // If not, return immediately.
  if (! RangeRetrievalSpecifierAttribute.prototype.hasRangeAttributes(result)) {
    callback(null, result);
    return;
  }

  // Parse the range attributes that were provided. If the range attributes are null
  // or indicate that the range is complete, return the result.
  var rangeAttributes = RangeRetrievalSpecifierAttribute.prototype.getRangeAttributes(result);
  if ((! rangeAttributes) || (rangeAttributes.length <= 0)) {
    callback(null, result);
    return;
  }

  // Parse each of the range attributes. Merge the range attributes into
  // the properly named property.
  var queryAttributes = [];
  _.each(rangeAttributes, function(rangeAttribute, index) {
    // Merge existing range into the properly named property.
    if (! result[rangeAttribute.attributeName]) result[rangeAttribute.attributeName] = [];
    Array.prototype.push.apply(result[rangeAttribute.attributeName], result[rangeAttribute.toString()]);
    delete(result[rangeAttribute.toString()]);

    // Build our ldap query attributes with the proper attribute;range= tags to
    // get the next sequence of data.
    var queryAttribute = rangeAttribute.next();
    if ((queryAttribute) && (! queryAttribute.isComplete())) {
      queryAttributes.push(queryAttribute.toString());
    }
  });

  // If we're at the end of the range (i.e. all items retrieved), return the result.
  if (queryAttributes.length <= 0) {
    log.debug('All attribute ranges %j retrieved for %s', rangeAttributes, result.dn);
    callback(null, result);
    return;
  }

  log.debug('Attribute range retrieval specifiers %j found for "%s". Next range: %j',
            rangeAttributes, result.dn, queryAttributes);
  // Execute the query again with the query attributes updated.
  opts = _.defaults({ filter: '(distinguishedName='+parseDistinguishedName(result.dn)+')',
                      attributes: queryAttributes }, opts);
  search.call(self, opts, function onSearch(err, results) {
    if (err) {
      callback(err);
      return;
    }

    // Should be only one result
    var item = (results || [])[0];
    for(var property in item) {
      if (item.hasOwnProperty(property)) {
        if (! result[property]) result[property] = [];
        if (_.isArray(result[property])) {
          Array.prototype.push.apply(result[property], item[property]);
        }
      }
    }
    callback(null, result);
  });
}

/**
 * Checks to see if any of the specified attributes are the wildcard
 * '*" attribute.
 * @private
 * @params {Array} attributes - The attributes to inspect.
 * @returns {Boolean}
 */
function shouldIncludeAllAttributes(attributes) {
  return((typeof(attributes) !== 'undefined') &&
         ((attributes.length === 0) ||
          _.any(attributes || [], function(attribute) {
           return(attribute === '*');
         }))
  );
}

/**
 * Gets the required ldap attributes for group related queries in order to
 * do recursive queries, etc.
 *
 * @private
 * @params {Object} [opts] Optional LDAP query string parameters to execute. { scope: '', filter: '', attributes: [ '', '', ... ], sizeLimit: 0, timelimit: 0 }
 */
function getRequiredLdapAttributesForGroup(opts) {
  if (shouldIncludeAllAttributes((opts || {}).attributes)) {
    return([ ]);
  }
  return(_.union([ 'dn', 'objectCategory', 'groupType', 'cn' ], 
                 includeGroupMembershipFor(opts, 'group') ? [ 'member' ] : []));
}

/**
 * Gets the required ldap attributes for user related queries in order to
 * do recursive queries, etc.
 *
 * @private
 * @params {Object} [opts] Optional LDAP query string parameters to execute. { scope: '', filter: '', attributes: [ '', '', ... ], sizeLimit: 0, timelimit: 0 }
 */
function getRequiredLdapAttributesForUser(opts) {
  if (shouldIncludeAllAttributes((opts || {}).attributes)) {
    return([ ]);
  }
  return(_.union([ 'dn', 'cn' ], 
                 includeGroupMembershipFor(opts, 'user') ? [ 'member' ] : []));
}

/**
 * Retrieves / merges the attributes for the query.
 */
function joinAttributes() {
  for (var index = 0, length = arguments.length; index < length; index++){
    if (shouldIncludeAllAttributes(arguments[index])) {
      return([ ]);
    }
  }
  return(_.union.apply(this, arguments));
}

/**
 * Picks only the requested attributes from the ldap result. If a wildcard or
 * empty result is specified, then all attributes are returned.
 * @private
 * @params {Object} result The ldap result
 * @params {Array} attributes The desired or wanted attributes
 * @returns {Object} A copy of the object with only the requested attributes
 */
function pickAttributes(result, attributes) {
  if (shouldIncludeAllAttributes(attributes)) {
    attributes = function() { 
      return(true); 
    };
  }
  return(_.pick(result, attributes));
}

/**
 * Gets all of the groups that the specified distinguishedName (DN) belongs to.
 * 
 * @private
 * @param {Object} [opts] Optional LDAP query string parameters to execute. { scope: '', filter: '', attributes: [ '', '', ... ], sizeLimit: 0, timelimit: 0 }
 * @param {String} dn The distinguishedName (DN) to find membership of.
 * @param {Function} callback The callback to execute when completed. callback(err: {Object}, groups: {Array[Group]})
 */
function getGroupMembershipForDN(opts, dn, stack, callback) {
  var self = this;
   
  if (typeof(stack) === 'function') {
    callback = stack;
    stack = undefined;
  }
  if (typeof(dn) === 'function') {
    callback = dn;
    dn = opts;
    opts = undefined;
  }
  if (typeof(opts) === 'string') {
    stack = dn;
    dn = opts;
    opts = undefined;
  }
  log.trace('getGroupMembershipForDN(%j,%s,stack:%j)', opts, dn, (stack || []).length);

  // Ensure that a valid DN was provided. Otherwise abort the search.
  if (! dn) {
    var error = new Error('No distinguishedName (dn) specified for group membership retrieval.');
    log.error(error);
    if (hasEvents('error')) self.emit('error', error);
    return(callback(error));
  }

  //  Note: Microsoft provides a 'Transitive Filter' for querying nested groups.
  //        i.e. (member:1.2.840.113556.1.4.1941:=<userDistinguishedName>)
  //        However this filter is EXTREMELY slow. Recursively querying ActiveDirectory
  //        is typically 10x faster.
  opts = _.defaults(_.omit(opts || {}, 'filter', 'scope', 'attributes'), {
    filter: '(member='+parseDistinguishedName(dn)+')',
    scope: 'sub',
    attributes: joinAttributes((opts || {}).attributes || defaultAttributes.group, [ 'groupType' ])
  });
  search.call(self, opts, function(err, results) {
    if (err) {
      callback(err);
      return;
    }

    var groups = [];
    async.forEach(results, function(group, asyncCallback) {
      // accumulates discovered groups
      if (typeof(stack) !== 'undefined') {
        if (!_.findWhere(stack, { cn: group.cn })) {
          stack.push(new Group(group));
        } else {
          // ignore groups already found
          return(asyncCallback());
        }

        _.each(stack,function(s) {
          if (!_.findWhere(groups, { cn: s.cn })) {
            groups.push(s);
          }
        });
      }

      if (isGroupResult(group)) {
        log.debug('Adding group "%s" to %s"', group.dn, dn);
        groups.push(new Group(group));

        // Get the groups that this group may be a member of.
        log.debug('Retrieving nested group membership for group "%s"', group.dn);
        getGroupMembershipForDN.call(self, opts, group.dn, groups, function(err, nestedGroups) {
          if (err) {
            asyncCallback(err);
            return;
          }

          nestedGroups = _.map(nestedGroups, function(nestedGroup) {
            if (isGroupResult(nestedGroup)) {
              return(new Group(nestedGroup));
            }
          });
          log.debug('Group "%s" which is a member of group "%s" has %d nested group(s). Nested: %j',
                    group.dn, dn, nestedGroups.length, _.map(nestedGroups, function(group) {
                     return(group.dn);
                   }));
          Array.prototype.push.apply(groups, nestedGroups);
          asyncCallback();
        });
      }
      else asyncCallback();
    }, function(err) {
       if (err) {
        callback(err);
        return;
      }

      // Remove the duplicates from the list.
      groups =  _.uniq(_.sortBy(groups, function(group) { return(group.cn || group.dn); }), false, function(group) {
        return(group.dn);
      });

      log.info('Group "%s" has %d group(s). Groups: %j', dn, groups.length, _.map(groups, function(group) {
         return(group.dn);
      }));
      callback(err, groups);
    });
  });
}

/**
 * For the specified filter, return the distinguishedName (dn) of all the matched entries.
 *
 * @private
 * @param {Object} [opts] Optional LDAP query string parameters to execute. { scope: '', filter: '', attributes: [ '', '', ... ], sizeLimit: 0, timelimit: 0 }
 * @params {Object|String} filter The LDAP filter to execute. Optionally a custom LDAP query object can be specified. { scope: '', filter: '', attributes: [ '', '', ... ], sizeLimit: 0, timelimit: 0 }
 * @param {Function} callback The callback to execute when completed. callback(err: {Object}, dns: {Array[String]})
 */
function getDistinguishedNames(opts, filter, callback) {
  var self = this;

  if (typeof(filter) === 'function') {
    callback = filter;
    filter = opts;
    opts = undefined;
  }
  if (typeof(opts) === 'string') {
    filter = opts;
    opts = undefined;
  }
  log.trace('getDistinguishedNames(%j,%j)', opts, filter);

  opts = _.defaults(_.omit(opts || {}, 'attributes'), {
    filter: filter,
    scope: 'sub',
    attributes: joinAttributes((opts || {}).attributes || [], [ 'dn' ])
  });
  search.call(self, opts, function(err, results) {
    if (err) {
      if (callback) callback(err);
      return;
    }

    // Extract just the DN from the results
    var dns =  _.map(results, function(result) {
      return(result.dn);
    });
    log.info('%d distinguishedName(s) found for LDAP query: "%s". Results: %j',
             results.length, truncateLogOutput(opts.filter), results);
    callback(null, dns);
  });
}

/**
 * Gets the distinguished name for the specified user (userPrincipalName/email or sAMAccountName).
 *
 * @private
 * @param {Object} [opts] Optional LDAP query string parameters to execute. { scope: '', filter: '', attributes: [ '', '', ... ], sizeLimit: 0, timelimit: 0 }
 * @param {String} username The name of the username to retrieve the distinguishedName (dn).
 * @param {Function} callback The callback to execute when completed. callback(err: {Object}, dn: {String})
 */
function getUserDistinguishedName(opts, username, callback) {
  var self = this;

  if (typeof(username) === 'function') {
    callback = username;
    username = opts;
    opts = undefined;
  }
  log.trace('getDistinguishedName(%j,%s)', opts, username);

  // Already a dn?
  if (isDistinguishedName.call(self, username)) {
    log.debug('"%s" is already a distinguishedName. NOT performing query.', username);
    callback(null, username);
    return;
  }

  getDistinguishedNames.call(self, opts, getUserQueryFilter(username), function(err, dns) {
    if (err) {
      callback(err);
      return;
    }

    log.info('%d distinguishedName(s) found for user: "%s". Returning first dn: "%s"',
             (dns || []).length, username, (dns || [])[0]);
    callback(null, (dns || [])[0]);
  });
}

/**
 * Gets the distinguished name for the specified group (cn).
 *
 * @private
 * @param {Object} [opts] Optional LDAP query string parameters to execute. { scope: '', filter: '', attributes: [ '', '', ... ], sizeLimit: 0, timelimit: 0 }
 * @param {String} groupName The name of the group to retrieve the distinguishedName (dn).
 * @param {Function} callback The callback to execute when completed. callback(err: {Object}, dn: {String})
 */
function getGroupDistinguishedName(opts, groupName, callback) {
  var self = this;

  if (typeof(groupName) === 'function') {
    callback = groupName;
    groupName = opts;
    opts = undefined;
  }
  log.trace('getGroupDistinguishedName(%j,%s)', opts, groupName);

  // Already a dn?
  if (isDistinguishedName.call(self, groupName)) {
    log.debug('"%s" is already a distinguishedName. NOT performing query.', groupName);
    callback(null, groupName);
    return;
  }

  getDistinguishedNames.call(self, opts, getGroupQueryFilter(groupName), function(err, dns) {
    if (err) {
      callback(err);
      return;
    }

    log.info('%d distinguishedName(s) found for group "%s". Returning first dn: "%s"',
             (dns || []).length, groupName, (dns || [])[0]);
    callback(null, (dns || [])[0]);
  });  
}

/**
 * Gets the currently configured default attributes
 *
 * @private
 */
ActiveDirectory.prototype._getDefaultAttributes = function _getDefaultAttributes() {
  return(_.defaults({}, defaultAttributes));
};

/**
 * Gets the currently configured default user attributes
 *
 * @private
 */
ActiveDirectory.prototype._getDefaultUserAttributes = function _getDefaultUserAttributes() {
  return(_.defaults({}, (defaultAttributes || {}).user));
};

/**
 * Gets the currently configured default group attributes
 *
 * @private
 */
ActiveDirectory.prototype._getDefaultGroupAttributes = function _getDefaultGroupAttributes() {
  return(_.defaults({}, (defaultAttributes || {}).group));
};
 
/**
 * For the specified group, retrieve all of the users that belong to the group.
 *
 * @public
 * @param {Object} [opts] Optional LDAP query string parameters to execute. { scope: '', filter: '', attributes: [ '', '', ... ], sizeLimit: 0, timelimit: 0 }
 * @param {String} groupName The name of the group to retrieve membership from.
 * @param {Function} callback The callback to execute when completed. callback(err: {Object}, users: {Array[User]})
 */
ActiveDirectory.prototype.getUsersForGroup = function getUsersForGroup(opts, groupName, callback) {
  var self = this;

  if (typeof(groupName) === 'function') {
    callback = groupName;
    groupName = opts;
    opts = undefined;
  }
  log.trace('getUsersForGroup(%j,%s)', opts, groupName);

  var users = [];
  var groups = [];

  self.findGroup(_.defaults({}, _.omit(opts || {}, 'attributes'), {
                   attributes: joinAttributes((opts || {}).attributes || defaultAttributes.group, [ 'member' ])
                 }), 
                 groupName, function(err, group) {
    if (err) {
      if (callback) callback(err);
      return;
    }

    // Group not found
    if (! group) {
      if (callback) callback(null, group);
      return;
    }
    // If only one result found, encapsulate result into array.
    if (typeof(group.member) === 'string') {
      group.member = [ group.member ];
    }

    /**
     * Breaks the large array into chucks of the specified size.
     * @param {Array} arr The array to break into chunks
     * @param {Number} chunkSize The size of each chunk.
     * @returns {Array} The resulting array containing each chunk
     */
    function chunk(arr, chunkSize) {
      var result = [];
      for (var index = 0, length = arr.length; index < length; index += chunkSize) {
        result.push(arr.slice(index,index + chunkSize));
      }
      return(result);
    }

    // We need to break this into the default size queries so
    // we can have them running concurrently.
    var chunks = chunk(group.member || [], defaultPageSize);
    if (chunks.length > 1) {
      log.debug('Splitting %d member(s) of "%s" into %d parallel chunks',
                (group.member || []).length, groupName, chunks.length);
    }
    var chunksProcessed = 0;
    async.each(chunks, function getUsersForGroup_ChunkItem(members, asyncChunkCallback) {
      // We're going to build up a bulk LDAP query so we can reduce
      // the number of round trips to the server. We need to get
      // additional details about each 'member' to determine if
      // it is a group or another user. If it's a group, we need
      // to recursively retrieve the members of that group.
      var filter = _.reduce(members || [], function(memo, member, index) {
        return(memo+'(distinguishedName='+parseDistinguishedName(member)+')');
      }, '');
      filter = '(&(|(objectCategory=User)(objectCategory=Group))(|'+filter+'))';

      var localOpts = {
        filter: filter,
        scope: 'sub',
        attributes: joinAttributes((opts || {}).attributes || defaultAttributes.user || [], 
                            getRequiredLdapAttributesForUser(opts), [ 'groupType' ])
      };
      search.call(self, localOpts, function onSearch(err, members) {
        if (err) {
          asyncChunkCallback(err);
          return;
        }

        // Parse the results in parallel.
        async.forEach(members, function(member, asyncCallback) {
          // If a user, no groupType will be specified.
          if (! member.groupType) {
            var user = new User(pickAttributes(member, (opts || {}).attributes || defaultAttributes.user));
            self.emit(user);
            users.push(user);
            asyncCallback();
          }
          else {
            // We have a group, recursively get the users belonging to this group.
            self.getUsersForGroup(opts, member.cn, function(err, nestedUsers) {
              users.push.apply(users, nestedUsers);
              asyncCallback();
            });
          }
        }, function(err) {
          if (chunks.length > 1) {
            log.debug('Finished processing chunk %d/%d', ++chunksProcessed, chunks.length);
          }
          asyncChunkCallback(err);
        });
      });
    }, function getUsersForGroup_ChunkComplete(err) {
      // Remove duplicates
      users = _.uniq(users, function(user) {
        return(user.dn || user);
      });
      

/*
      // Remove the dn that was added for duplicate detection if not requested.
      if (! _.any((opts || {}).attributes || defaultAttributes.user, function(attribute) {
        return(attribute === 'dn');
      })) {
        users = _.each(users, function(user) {
          delete(users.dn);
        });
      }
*/
      log.info('%d user(s) belong in the group "%s"', users.length, groupName);
      if (callback) callback(null, users);
    });
  });
};

/**
 * For the specified username, get all of the groups that the user is a member of.
 *
 * @public
 * @param {Object} [opts] Optional LDAP query string parameters to execute. { scope: '', filter: '', attributes: [ '', '', ... ], sizeLimit: 0, timelimit: 0 }
 * @param {String} username The username to retrieve membership information about.
 * @param {Function} [callback] The callback to execute when completed. callback(err: {Object}, groups: {Array[Group]})
 */
ActiveDirectory.prototype.getGroupMembershipForUser = function getGroupMembershipForUser(opts, username, callback) {
  var self = this;

  if (typeof(username) === 'function') {
    callback = username;
    username = opts;
    opts = undefined;
  }
  log.trace('getGroupMembershipForUser(%j,%s)', opts, username);

  getUserDistinguishedName.call(self, opts, username, function(err, dn) {
    if (err) {
      if (callback) callback(err);
      return;
    }  

    if (! dn) {
      log.warn('Could not find a distinguishedName for the specified username: "%s"', username);
      if (callback) callback();
      return;
    }
    getGroupMembershipForDN.call(self, opts, dn, function(err, groups) {
      if (err) {
        if (callback) callback(err);
        return;
      }
      
      var results = [];
      _.each(groups, function(group) {
        var result = new Group(pickAttributes(group, (opts || {}).attributes || defaultAttributes.group));
        self.emit(result);
        results.push(result);
      });
      if (callback) callback(err, results);
    });
  });
};

/**
 * For the specified group, get all of the groups that the group is a member of.
 *
 * @public
 * @param {Object} [opts] Optional LDAP query string parameters to execute. { scope: '', filter: '', attributes: [ '', '', ... ], sizeLimit: 0, timelimit: 0 }
 * @param {String} groupName The group to retrieve membership information about.
 * @param {Function} [callback] The callback to execute when completed. callback(err: {Object}, groups: {Array[Group]})
 */
ActiveDirectory.prototype.getGroupMembershipForGroup = function getGroupMembershipForGroup(opts, groupName, callback) {
  var self = this;
  
  if (typeof(groupName) === 'function') {
    callback = groupName;
    groupName = opts;
    opts = undefined;
  }
  log.trace('getGroupMembershipForGroup(%j,%s)', opts, groupName);

  getGroupDistinguishedName.call(self, opts, groupName, function(err, dn) {
    if (err) {
      if (callback) callback(err);
      return;
    }  

    if (! dn) {
      log.warn('Could not find a distinguishedName for the specified group name: "%s"', groupName);
      if (callback) callback();
      return;
    }
    getGroupMembershipForDN.call(self, opts, dn, function(err, groups) {
      if (err) {
        if (callback) callback(err);
        return;
      }

      var results = [];
      _.each(groups, function(group) {
        var result = new Group(pickAttributes(group, (opts || {}).attributes || defaultAttributes.group));
        self.emit(result);
        results.push(result);
      });
      if (callback) callback(err, results);
    });
  });
};

/**
 * Checks to see if the specified username exists.
 *
 * @param {Object} [opts] Optional LDAP query string parameters to execute. { scope: '', filter: '', attributes: [ '', '', ... ], sizeLimit: 0, timelimit: 0 }
 * @param {String} username The username to check to see if it exits.
 * @param {Function} callback The callback to execute when completed. callback(err: {Object}, result: {Boolean})
 */ 
ActiveDirectory.prototype.userExists = function userExists(opts, username, callback) {
  var self = this;

  if (typeof(username) === 'function') {
    callback = username;
    username = opts;
    opts = undefined;
  }
  log.trace('userExists(%j,%s)', opts, username);

  self.findUser(opts, username, function(err, user) {
    if (err) {
      callback(err);
      return;
    }

    log.info('"%s" %s exist.', username, (user != null) ? 'DOES' : 'DOES NOT');
    callback(null, user != null);
  });
};

/**
 * Checks to see if the specified group exists.
 *
 * @param {Object} [opts] Optional LDAP query string parameters to execute. { scope: '', filter: '', attributes: [ '', '', ... ], sizeLimit: 0, timelimit: 0 }
 * @param {String} groupName The group to check to see if it exists.
 * @param {Function} callback The callback to execute when completed. callback(err: {Object}, result: {Boolean})
 */ 
ActiveDirectory.prototype.groupExists = function groupExists(opts, groupName, callback) {
  var self = this;

  if (typeof(groupName) === 'function') {
    callback = groupName;
    groupName = opts;
    opts = undefined;
  }
  log.trace('groupExists(%j,%s)', opts, groupName);

  self.findGroup(opts, groupName, function(err, result) {
    if (err) {
      callback(err);
      return;
    }

    log.info('"%s" %s exist.', groupName, (result != null) ? 'DOES' : 'DOES NOT');
    callback(null, result != null);
  });
};

/**
 * Checks to see if the specified user is a member of the specified group.
 *
 * @param {Object} [opts] Optional LDAP query string parameters to execute. { scope: '', filter: '', attributes: [ '', '', ... ], sizeLimit: 0, timelimit: 0 }
 * @param {String} username The username to check for membership.
 * @param {String} groupName The group to check for membership.
 * @param {Function} callback The callback to execute when completed. callback(err: {Object}, result: {Boolean})
 */
ActiveDirectory.prototype.isUserMemberOf = function isUserMemberOf(opts, username, groupName, callback) {
  var self = this;

  if (typeof(groupName) === 'function') {
    callback = groupName;
    groupName = username;
    username = opts;
    opts = undefined;
  }
  log.trace('isUserMemberOf(%j,%s,%s)', opts, username, groupName);

  opts = _.defaults(_.omit(opts || {}, 'attributes'), {
    attributes: [ 'cn', 'dn' ] 
  });
  self.getGroupMembershipForUser(opts, username, function(err, groups) {
    if (err) {
      callback(err);
      return;
    }
    if ((! groups) || (groups.length === 0)) {
      log.info('"%s" IS NOT a member of "%s". No groups found for user.', username, groupName);
      callback(null, false);
      return;
    }

    // Check to see if the group.distinguishedName or group.cn matches the list of
    // retrieved groups.
    var lowerCaseGroupName = (groupName || '').toLowerCase();
    var result = _.any(groups, function(item) {
      return(((item.dn || '').toLowerCase() === lowerCaseGroupName) ||
             ((item.cn || '').toLowerCase() === lowerCaseGroupName));
     });
    log.info('"%s" %s a member of "%s"', username, result ? 'IS' : 'IS NOT', groupName);
    callback(null, result);
  });
};

/**
 * Checks to see if group membership for the specified type is enabled.
 *
 * @param {Object} [opts] The options to inspect. If not specified, uses this.opts.
 * @param {String} name The name of the membership value to inspect. Values: (all|user|group)
 * @returns {Boolean} True if the specified membership is enabled.
 */
function includeGroupMembershipFor(opts, name) {
  if (typeof(opts) === 'string') {
    name = opts;
    opts = this.opts;
  }

  var lowerCaseName = (name || '').toLowerCase();
  return(_.any(((opts || this.opts || {}).includeMembership || []), function(i) {
    i = i.toLowerCase();
    return((i === 'all') || (i === lowerCaseName));
  }));
}

/**
 * Perform a generic search for the specified LDAP query filter. This function will return both
 * groups and users that match the specified filter. Any results not recognized as a user or group
 * (i.e. computer accounts, etc.) can be found in the 'other' attribute / array of the result.
 *
 * @public
 * @param {Object} [opts] Optional LDAP query string parameters to execute. { scope: '', filter: '', attributes: [ '', '', ... ], sizeLimit: 0, timelimit: 0 }. Optionally, if only a string is provided, then the string is assumed to be an LDAP filter.
 * @param {Function} callback The callback to execute when completed. callback(err: {Object}, { users: [ User ], groups: [ Group ], other: [ ] )
 */
ActiveDirectory.prototype.find = function find(opts, callback) {
  var self = this;

  if (typeof(opts) === 'function') {
    callback = opts;
    opts = undefined;
  }
  if (typeof(opts) === 'string') {
    opts = {
      filter: opts
    };
  }
  log.trace('find(%j)', opts);

  var localOpts = _.defaults(_.omit(opts || {}, 'attributes'), {
    scope: 'sub',
    attributes: joinAttributes((opts || {}).attributes || [], defaultAttributes.group || [], defaultAttributes.user || [], 
                        getRequiredLdapAttributesForGroup(opts), getRequiredLdapAttributesForUser(opts), 
                        [ 'objectCategory' ])
  });
  search.call(self, localOpts, function onFind(err, results) {
    if (err) {
      if (callback) callback(err);
      return;
    }

    if ((! results) || (results.length === 0)) {
      log.warn('No results found for query "%s"', truncateLogOutput(localOpts.filter));
      if (callback) callback();
      self.emit('done');
      return;
    }

    var result = {
      users: [],
      groups: [],
      other: []
    };

    // Parse the results in parallel.
    async.forEach(results, function(item, asyncCallback) {
      if (isGroupResult(item)) {
        var group = new Group(pickAttributes(item, (opts || {}).attributes || defaultAttributes.group));
        result.groups.push(group);
        // Also retrieving user group memberships?
        if (includeGroupMembershipFor(opts, 'group')) {
          getGroupMembershipForDN.call(self, opts, group.dn, function(err, groups) {
            if (err) return(asyncCallback(err));

            group.groups = groups;
            self.emit('group', group);
            asyncCallback();
          });
        } else {
          self.emit('group', group);
          asyncCallback();
        }
      }
      else if (isUserResult(item)) {
        var user = new User(pickAttributes(item, (opts || {}).attributes || defaultAttributes.user));
        result.users.push(user);
        // Also retrieving user group memberships?
        if (includeGroupMembershipFor(opts, 'user')) {
          getGroupMembershipForDN.call(self, opts, user.dn, function(err, groups) {
            if (err) return(asyncCallback(err));

            user.groups = groups;
            self.emit('user', user);
            asyncCallback();
          });
        } else {
          self.emit('user', user);
          asyncCallback();
        }
      }
      else {
        var other = pickAttributes(item, (opts || {}).attributes || _.union(defaultAttributes.user, defaultAttributes.group));
        result.other.push(other);
        self.emit('other', other);
        asyncCallback();
      }

    }, function(err) {
      if (err) {
        if (callback) callback(err);
        return;
      }

      log.info('%d group(s), %d user(s), %d other found for query "%s". Results: %j',
               result.groups.length, result.users.length, result.other.length,
               truncateLogOutput(opts.filter), result);
      self.emit('groups', result.groups);
      self.emit('users', result.users);

      if (callback) callback(null, result);
    });
  });
};

/**
 * Perform a generic search on the Deleted Objects container for active directory. For this function
 * to work correctly, the tombstone feature for active directory must be enabled. A tombstoned object
 * has most of the attributes stripped from the object.
 *
 * @public
 * @param {Object} [opts] Optional LDAP query string parameters to execute. { scope: '', filter: '', attributes: [ '', '', ... ], sizeLimit: 0, timelimit: 0 }. Optionally, if only a string is provided, then the string is assumed to be an LDAP filter.
 * @param {Function} callback The callback to execute when completed. callback(err: {Object}, result: [ ])
 */
ActiveDirectory.prototype.findDeletedObjects = function find(opts, callback) {
  var self = this;

  if (typeof(opts) === 'function') {
    callback = opts;
    opts = undefined;
  }
  if (typeof(opts) === 'string') {
    opts = {
      filter: opts
    };
  }
  log.trace('findDeletedObjects(%j)', opts);

  var defaultDeletedAttributes = [
    'attributeID', 'attributeSyntax', 'dnReferenceUpdate' , 'dNSHostName' , 'flatName',
    'governsID', 'groupType', 'instanceType', 'lDAPDisplayName', 'legacyExchangeDN',
    'mS-DS-CreatorSID', 'mSMQOwnerID', 'nCName', 'objectClass', 'objectGUID', 'objectSid',
    'oMSyntax', 'proxiedObjectName', 'replPropertyMetaData', 'sAMAccountName', 'securityIdentifier',
    'sIDHistory', 'subClassOf', 'systemFlags', 'trustPartner', 'trustDirection', 'trustType',
    'trustAttributes', 'userAccountControl', 'uSNChanged', 'uSNCreated', 'whenCreated',
    'msDS-AdditionalSam­AccountName', 'msDS-Auxiliary-Classes', 'msDS-Entry-Time-To-Die',
    'msDS-IntId', 'msSFU30NisDomain', 'nTSecurityDescriptor', 'uid' 
  ];

  /**
   * Performs the actul search of the specified baseDN for any deleted (tombstoned) objects.
   * @param {String} baseDN The baseDN to search on.
   * @param {Object} opts The ldapjs query options.
   */
  function searchDeletedObjects(baseDN, opts) {
    search.call(self, baseDN, _.defaults({}, opts, { includeDeleted: true }), function onFind(err, results) {
      if (err) {
        if (callback) callback(err);
        return;
      }

      if ((! results) || (results.length === 0)) {
        log.warn('No deleted objects found for query "%s"', truncateLogOutput(opts.filter));
        if (callback) callback();
        self.emit('done');
        return;
      }

      var deletedItems = [];

      // Parse the results in parallel.
      _.forEach(deletedItemss, function(item) {
        var deletedItem = pickAttributes(item, (opts | {}).attributes || []);
        self.emit('entry:deleted', deletedItem);
        deletedItems.push(deletedItem);
      });

      log.info('%d deleted objects found for query "%s". Results: %j',
               deletedItems.length, truncateLogOutput(localOpts.filter), deletedItems);
      self.emit('deleted', deletedItems);
      if (callback) callback(null, deletedItems);
    });
  }

  var localOpts = _.defaults(opts || {}, {
    scope: 'one',
    attributes: joinAttributes((opts || {}).attributes || [], defaultDeletedAttributes),
    controls: [ ]
  });
  // Get the BaseDN for the tree
  if (! localOpts.baseDN) {
    log.debug('No baseDN specified for Deleted Object. Querying RootDSE at %s.', self.opts.url);
    ActiveDirectory.prototype.getRootDSE(self.opts.url, [ 'defaultNamingContext' ], function(err, result) {
      if (err) {
        if (callback) callback(err);
        return;
      }

      log.info('Retrieved defaultNamingContext (%s) from RootDSE at %s.', result.defaultNamingContext, self.opts.url);
      searchDeletedObjects('CN=Deleted Objects,' + result.defaultNamingContext, localOpts);
    });
  }
  else searchDeletedObjects(localOpts.baseDN, localOpts);
};

/**
 * Retrieves the specified group.
 *
 * @public
 * @param {Object} [opts] Optional LDAP query string parameters to execute. { scope: '', filter: '', attributes: [ '', '', ... ], sizeLimit: 0, timelimit: 0 }
 * @param {String} groupName The group (cn) to retrieve information about. Optionally can pass in the distinguishedName (dn) of the group to retrieve.
 * @param {Function} callback The callback to execute when completed. callback(err: {Object}, group: {Group})
 */
ActiveDirectory.prototype.findGroup = function findGroup(opts, groupName, callback) {
  var self = this;

  if (typeof(groupName) === 'function') {
    callback = groupName;
    groupName = opts;
    opts = undefined;
  }
  if (typeof(opts) === 'string') {
    groupName = opts;
    opts = undefined;
  }
  log.trace('findGroup(%j,%s)', opts, groupName);

  var localOpts = _.defaults(_.omit(opts || {}, 'attributes'), {
    filter: getGroupQueryFilter.call(self, groupName),
    scope: 'sub',
    attributes: joinAttributes((opts || {}).attributes || defaultAttributes.group, getRequiredLdapAttributesForGroup(opts))
  });
  search.call(self, localOpts, function onSearch(err, results) {
    if (err) {
      if (callback) callback(err);
      return;
    }

    if ((! results) || (results.length === 0)) {
      log.warn('Group "%s" not found for query "%s"', groupName, truncateLogOutput(localOpts.filter));
      if (callback) callback();
      return;
    }

    var group = new Group(pickAttributes(results[0], (opts || {}).attributes || defaultAttributes.group));
    log.info('%d group(s) found for query "%s". Returning first group: %j',
             results.length, truncateLogOutput(localOpts.filter), group);
    // Also retrieving user group memberships?
    if (includeGroupMembershipFor(opts, 'group')) {
      getGroupMembershipForDN.call(self, opts, group.dn, function(err, groups) {
        if (err) {
          if (callback) callback(err);
          return;
        }

        group.groups = groups;
        self.emit('group', group);
        if (callback) callback(err, group);
      });
    }
    else {
      self.emit('group', group);
      if (callback) callback(err, group);
    }
  });
};

/**
 * Perform a generic search for groups that match the specified filter. The default LDAP filter for groups is
 * specified as (&(objectClass=group)(!(objectClass=computer))(!(objectClass=user))(!(objectClass=person)))
 *
 * @public
 * @param {Object} [opts] Optional LDAP query string parameters to execute. { scope: '', filter: '', attributes: [ '', '', ... ], sizeLimit: 0, timelimit: 0 }. Optionally, if only a string is provided, then the string is assumed to be an LDAP filter that will be appended as the last parameter in the default LDAP filter.
 * @param {Function} callback The callback to execute when completed. callback(err: {Object}, groups: [ Group ])
 */
ActiveDirectory.prototype.findGroups = function findGroup(opts, callback) {
  var self = this;
  var defaultGroupFilter = '(objectClass=group)(!(objectClass=computer))(!(objectClass=user))(!(objectClass=person))';

  if (typeof(opts) === 'function') {
    callback = opts;
    opts = '';
  }
  if ((typeof(opts) === 'string') && (opts)) {
    opts = {
      filter: '(&'+defaultGroupFilter+getCompoundFilter(opts)+')'
    };
  }

  log.trace('findGroups(%j)', opts);

  var localOpts = _.defaults(_.omit(opts || {}, 'attributes'), {
    filter: '(&'+defaultGroupFilter+')',
    scope: 'sub',
    attributes: joinAttributes((opts || {}).attributes || defaultAttributes.group || [], getRequiredLdapAttributesForGroup(opts), 
                        [ 'groupType' ])
  });
  search.call(self, localOpts, function onSearch(err, results) {
    if (err) {
      if (callback) callback(err);
      return;
    }

    if ((! results) || (results.length === 0)) {
      log.warn('No groups found matching query "%s"', truncateLogOutput(localOpts.filter));
      if (callback) callback();
      return;
    }

    var groups = [];

    // Parse the results in parallel.
    async.forEach(results, function(result, asyncCallback) {
      if (isGroupResult(result)) {
        var group = new Group(pickAttributes(result, (opts || {}).attributes || defaultAttributes.user));
        groups.push(group);

        // Also retrieving user group memberships?
        if (includeGroupMembershipFor(opts, 'group')) {
          getGroupMembershipForDN.call(self, opts, group.dn, function(err, groups) {
            if (err) return(asyncCallback(err));
  
            group.groups = groups;
            self.emit('group', group);
            asyncCallback();
          });
        }
        else {
          self.emit('group', group);
          asyncCallback();
        }
      }
      else asyncCallback();
    }, function(err) {
      if (err) {
        if (callback) callback(err);
        return;
      }

      log.info('%d group(s) found for query "%s". Groups: %j', groups.length, truncateLogOutput(localOpts.filter), groups);
      self.emit('groups', groups);
      if (callback) callback(null, groups);
    });
  });
};

/**
 * Retrieves the specified user.
 *
 * @public
 * @param {Object} [opts] Optional LDAP query string parameters to execute. { scope: '', filter: '', attributes: [ '', '', ... ], sizeLimit: 0, timelimit: 0 }
 * @param {String} username The username to retrieve information about. Optionally can pass in the distinguishedName (dn) of the user to retrieve.
 * @param {Boolean} [includeMembership] OBSOLETE; NOT NOT USE. Indicates if the results should include group memberships for the user. Defaults to false.
 * @param {Function} callback The callback to execute when completed. callback(err: {Object}, user: {User})
 */
ActiveDirectory.prototype.findUser = function findUser(opts, username, includeMembership, callback) {
  var self = this;

  if (typeof(includeMembership) === 'function') {
    callback = includeMembership;
    includeMembership = undefined;
  }
  if (typeof(username) === 'function') {
    callback = username;
    username = opts;
    opts = undefined;
  }
  if (typeof(username) === 'boolean') {
    includeMembership = username;
    username = opts;
  }
  if (typeof(opts) === 'string') {
    username = opts;
    opts = undefined;
  }
  log.trace('findUser(%j,%s,%s)', opts, username, includeMembership);

  var localOpts = _.defaults(_.omit(opts || {}, 'attributes'), {
    filter: getUserQueryFilter.call(self, username),
    scope: 'sub',
    attributes: joinAttributes((opts || {}).attributes || defaultAttributes.user || [], getRequiredLdapAttributesForUser(opts))
  });
  search.call(self, localOpts, function onSearch(err, results) {
    if (err) {
      if (callback) callback(err);
      return;
    }

    if ((! results) || (results.length === 0)) {
      log.warn('User "%s" not found for query "%s"', username, truncateLogOutput(localOpts.filter));
      if (callback) callback();
      return;
    }

    var user = new User(pickAttributes(results[0], (opts || {}).attributes || defaultAttributes.user));
    log.info('%d user(s) found for query "%s". Returning first user: %j', results.length, truncateLogOutput(localOpts.filter), user);

    // Also retrieving user group memberships?
    if (includeGroupMembershipFor(opts, 'user') || includeMembership) {
      getGroupMembershipForDN.call(self, opts, user.dn, function(err, groups) {
        if (err) {
          if (callback) callback(err);
          return;
        }

        user.groups = groups;
        self.emit('user', user);
        if (callback) callback(err, user);
      });
    }
    else {
      self.emit('user', user);
      if (callback) callback(err, user);
    }
  });
};

/**
 * Perform a generic search for users that match the specified filter. The default LDAP filter for users is
 * specified as (&(|(objectClass=user)(objectClass=person))(!(objectClass=computer))(!(objectClass=group)))
 *
 * @public
 * @param {Object} [opts] Optional LDAP query string parameters to execute. { scope: '', filter: '', attributes: [ '', '', ... ], sizeLimit: 0, timelimit: 0 }. Optionally, if only a string is provided, then the string is assumed to be an LDAP filter that will be appended as the last parameter in the default LDAP filter.
 * @param {Boolean} [includeMembership] OBSOLETE; NOT NOT USE. Indicates if the results should include group memberships for the user. Defaults to false.
 * @param {Function} callback The callback to execute when completed. callback(err: {Object}, users: [ User ])
 */
ActiveDirectory.prototype.findUsers = function findUsers(opts, includeMembership, callback) {
  var self = this;
  var defaultUserFilter = '(|(objectClass=user)(objectClass=person))(!(objectClass=computer))(!(objectClass=group))';

  if (typeof(includeMembership) === 'function') {
    callback = includeMembership;
    includeMembership = false;
  }
  if (typeof(opts) === 'function') {
    callback = opts;
    opts = '';
  }
  if ((typeof(opts) === 'string') && (opts)) {
    opts = {
      filter: '(&'+defaultUserFilter+getCompoundFilter(opts)+')'
    };
  }
  log.trace('findUsers(%j,%s)', opts, includeMembership);

  var localOpts = _.defaults(_.omit(opts || {}, 'attributes'), {
    filter: '(&'+defaultUserFilter+')',
    scope: 'sub',
    attributes: joinAttributes((opts || {}).attributes || defaultAttributes.user || [], 
                               getRequiredLdapAttributesForUser(opts), [ 'objectCategory' ])
  });
  search.call(self, localOpts, function onSearch(err, results) {
    if (err) {
      if (callback) callback(err);
      return;
    }

    if ((! results) || (results.length === 0)) {
      log.warn('No users found matching query "%s"', truncateLogOutput(localOpts.filter));
      if (callback) callback();
      return;
    }

    var users = [];

    // Parse the results in parallel.
    async.forEach(results, function(result, asyncCallback) {
      if (isUserResult(result)) {
        var user = new User(pickAttributes(result, (opts || {}).attributes || defaultAttributes.user));
        users.push(user);

        // Also retrieving user group memberships?
        if (includeGroupMembershipFor(opts, 'user') || includeMembership) {
          getGroupMembershipForDN.call(self, opts, user.dn, function(err, groups) {
            if (err) return(asyncCallback(err));
  
            user.groups = groups;
            self.emit('user', user);
            asyncCallback();
          });
        }
        else {
          self.emit('user', user);
          asyncCallback();
        }
      }
      else asyncCallback();
    }, function(err) {
      if (err) {
        if (callback) callback(err);
        return;
      }

      log.info('%d user(s) found for query "%s". Users: %j', users.length, truncateLogOutput(opts.filter), users);
      self.emit('users', users);
      if (callback) callback(null, users);
    });
  });
};

/**
 * Attempts to authenticate the specified username / password combination.
 *
 * @public
 * @param {String} username The username to authenticate.
 * @param {String} password The password to use for authentication.	
 * @param {Function} callback The callback to execute when the authenication is completed. callback(err: {Object}, authenticated: {Boolean})
 */
ActiveDirectory.prototype.authenticate = function authenticate(username, password, callback) {
  var self = this;
  log.trace('authenticate(%j,%s)', username, isPasswordLoggingEnabled ? password : '********');

  // Skip authentication if an empty username or password is provided.
  if ((! username) || (! password)) {
    var err = {
      'code': 0x31,
      'errno': 'LDAP_INVALID_CREDENTIALS',
      'description': 'The supplied credential is invalid'
    };
    return(callback(err, false));
  }

  var errorHandled = false;
  function handleError(err) {
    if (! errorHandled) {
      errorHandled = true;
      if (hasEvents.call(self, 'error')) self.emit('error', err);
      return(callback(err, false));
    }
  }

  var client = createClient.call(self);
  client.on('error', handleError);
  client.bind(username, password, function(err) {
    client.unbind();
    var message = util.format('Authentication %s for "%s" as "%s" (password: "%s")',
                              err ? 'failed' : 'succeeded',
                              self.opts.url, username, isPasswordLoggingEnabled ? password : '********');
    if (err) {
      log.warn('%s. Error: %s', message, err);
      return(handleError(err));
    }

    log.info(message);
    return(callback(err, true));
  });
};

/**
 * Retrieves the root DSE for the specified url
 *
 * @public
 * @param {String} url The url to retrieve the root DSE for.
 * @param {Array} [attributes] The optional list of attributes to retrieve. Returns all if not specified.
 * @param {Function} callback The callback to execute when the getRootDSE is completed. callback(err: {Object}, result: {Object})
 */
ActiveDirectory.prototype.getRootDSE = function getRootDSE(url, attributes, callback) {
  var self = this;
  if (typeof(attributes) === 'function') {
    callback = attributes;
    attributes = undefined;
  }
  if (typeof(url) === 'function') {
    callback = url;
    url = self.url || self.opts.url;
    attributes = undefined;
  }
  if (! url) throw new Error('No url specified for the root DSE. Please specify an ldap url in the following format: "ldap://yourdomain.com:389".');
  log.trace('getRootDSE(%s,%j)', url, attributes || [ '*' ]);

  /**
   * Inline function handle connection and result errors.
   *
   * @private
   **/
  function onClientError(err) {
    // Ignore ECONNRESET errors
    if ((err || {}).errno !== 'ECONNRESET') {
      log.error('An unhandled error occured when searching for the root DSE at "%s". Error: %j', url, err);
      if (hasEvents.call(self, 'error')) self.emit('error', err)
    }
  }

  var client = createClient.call(this, url);
  client.on('error', onClientError);
  // Anonymous bind
  client.bind('', '', function(err) {
    if (err) {
      log.error('Anonymous bind to "%s" failed. Error: %s', url, err);
      return(callback(err, false));
    }

    client.search('', { scope: 'base', attributes: attributes || [ '*' ], filter: '(objectClass=*)' }, function(err, result) {
      if (err) {
        log.error('Root DSE search failed for "%s". Error: %s', url, err);
        return(callback(err));
      }

      result.on('error', onClientError);
      result.on('end', function(result) {
        client.unbind();
      });
      result.on('searchEntry', function(entry) {
        callback(null, _.omit(entry.object, 'controls'));
      });
    });    
  });
};

module.exports = ActiveDirectory;
