var events = require('events');
var util = require('util');
var ldap = require('ldapjs');
var async = require('async');
var _ = require('underscore');

var User = require('./models/user');
var Group = require('./models/group');
var RangeRetrievalSpecifierAttribute = require('./rangeretrievalspecifierattribute');

var defaultAttributes = {
  user: [ 
    'userPrincipalName', 'sAMAccountName', /*'objectSID',*/ 'mail',
    'lockoutTime', 'whenCreated', 'pwdLastSet', 'userAccountControl',
    'employeeID', 'sn', 'givenName', 'initials', 'cn', 'displayName',
    'comment', 'description' 
  ],
  group: [
    'objectCategory',
    'distinguishedName',
    'cn',
    'description',
    'member'
  ]
};
var defaultReferrals = {
  enabled: false,
  // Active directory returns the following partitions as default referrals which we don't want to follow
  exclude: [
    'ldaps?://ForestDnsZones\\..*/.*',
    'ldaps?://DomainDnsZones\\..*/.*',
    'ldaps?://.*/CN=Configuration,.*'
  ]
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
  if (typeof(url) === 'object') {
    var opts = url;
    this.url = opts.url;
    this.baseDN = opts.baseDN;
    this.username = opts.username;
    this.password = opts.password;

    defaultAttributes = _.extend({}, defaultAttributes, opts.attributes || {});
    defaultReferrals = _.extend({}, defaultReferrals, opts.referrals || {});
  }
  else {
    this.url = url;
    this.baseDN = baseDN;
    this.username = username;
    this.password = password;

    defaultAttributes = _.extend({}, defaultAttributes, (defaults || {}).attributes || {});
    defaultReferrals = _.extend({}, defaultReferrals, (defaults || {}).referrals || {});
  }
  events.EventEmitter.call(this);
};
util.inherits(ActiveDirectory, events.EventEmitter);

/**
 * Checks to see if the value is a distinguished name.
 *
 * @private
 * @param {String} value The value to check to see if it's a distinguished name.
 * @returns {Boolean}
 */
function isDistinguishedName(value) {
  var self = this;

  if ((! value) || (value.length == 0)) return(false);

  var re = new RegExp('(([^=]+=.+),?)+', 'gi');
  //var re = new RegExp('^(.+)=(.+)' + (self || {}).baseDN + '$', 'gi');
  return(re.test(value));
}

/**
 * Parses the distinguishedName (dn) to remove any invalid characters or to
 * properly escape the request.
 *
 * @private
 * @param dn {String} The dn to parse.
 * @returns {String}
 */
function parseDistinguishedName(dn) {
  if (! dn) return(dn);

  // Currently a bug in ldapjs that isn't properly escaping DNs with ','
  // in the name.
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
  var self = this;

  if (! username) return('(objectCategory=User)');
  if (isDistinguishedName.call(self, username)) {
    return('(&(objectCategory=User)(distinguishedName='+parseDistinguishedName(username)+'))');
  }

  return('(&(objectCategory=User)(|(sAMAccountName='+username+')(userPrincipalName='+username+')))');
}
/**
 * Gets the ActiveDirectory LDAP query string for a group search.
 *
 * @private
 * @param {String} dn The distinguishedName (dn) of the group or user to find membership for.
 * @returns {String}
 */
function getGroupQueryFilter(groupName) {
  var self = this;

  if (! groupName) return('(objectCategory=Group');
  if (isDistinguishedName.call(self, groupName)) {
    return('(&(objectCategory=Group)(distinguishedName='+parseDistinguishedName(groupName)+'))');
  }

  return('(&(objectCategory=Group)(cn='+groupName+'))');
}

/**
 * Factory to create the LDAP client object.
 *
 * @private
 * @param {String} [url] The url to use when creating the LDAP client.
 */
function createClient(url) {
  // Attempt to get Url from the this instance.
  url = url || (this.url);
  if (! url) {
    throw 'No url specified for ActiveDirectory client.';
  }

  var client = ldap.createClient({ url: url });
  return(client);
}

/**
 * Checks to see if the specified referral or "chase" is allowed.
 * @param {String} referral The referral to inspect.
 * @returns {Boolean} True if the referral should be followed, false if otherwise.
 */
function isAllowedReferral(referral) {
  if (! defaultReferrals.enabled) return(false);
  if (! referral) return(false);

  return(! _.any(defaultReferrals.exclude, function(exclusion) {
    var re = new RegExp(exclusion, "i");
    return(re.test(referral));
  }));
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
  baseDN || (baseDN = self.baseDN);

  var pendingReferrals = [];
  var client = createClient.call(self);
  client.on('error', function(err) {
    // Ignore ECONNRESET errors
    if ((err || {}).errno !== 'ECONNRESET') {
      self.emit('error', err);
    }
  });
  client.bind(self.username, self.password, function(err) {
    if (err) {
      if (callback) callback(err);
      return;
    }

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
     * Occurs when a search entry is received. Cleans up the search entry and pushes it to the result set.
     * @param {Object} entry The entry received.
     */
    function onSearchEntry(entry) {
      var result = entry.object;
      delete result.controls; // Remove the controls array returned as part of the SearchEntry

      results.push(result);
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
          var referralClient = createClient.call(self, referralUrl);
          pendingReferrals.push(referralClient);

          // Bind using the primary credentials
          referralClient.bind(self.username, self.password, function(err) {
            // If the referral chase failed, fail silently.
            if (err) {
              removeReferral(referralClient);
              return;
            }

            referralClient.search(referralClient.url.DN, opts, function(err, res) {
              // If the referral chase / search failed, fail silently.
              if (err) {
                removeReferral(referralClient);
                return;
              }

              res.on('searchEntry', onSearchEntry);
              res.on('searchReference', onReferralChase);
              res.on('error', function(err) {
                removeReferral(referralClient);
              });
              res.on('end', function(result) {
                removeReferral(referralClient);
                onSearchEnd(result);
              });
            });
          });
        }
      }
    }

    /**
     * Occurs when a search error occurs.
     * @param {Object} err The error object or string.
     */
    function onSearchError(err) {
      self.emit('error', err);
      if (callback) callback(err);
    }

    /**
     * Occurs when a search results have all been processed.
     * @param {Object} result
     */
    function onSearchEnd(result) {
      client.unbind();
      if (pendingReferrals.length <= 0) {
        if (callback) callback(null, results);
      }
    }

    var results = [];
    client.search(baseDN, opts, function(err, res) {
      if (err) {
        if (callback) callback(err);
        return;
      }

      res.on('searchEntry', onSearchEntry);
      res.on('searchReference', onReferralChase);
      res.on('error', onSearchError);
      res.on('end', onSearchEnd);
    });
  });
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
  
  // Ensure that a valid DN was provided. Otherwise abort the search.
  if (! dn) {
    var error = new Error('No distinguishedName (dn) specified for group membership retrieval.');
    self.emit('error', error);
    if (callback) callback(error);
    return;
  }

  //  Note: Microsoft provides a 'Transitive Filter' for querying nested groups.
  //        i.e. (member:1.2.840.113556.1.4.1941:=<userDistinguishedName>)
  //        However this filter is EXTREMELY slow. Recursively querying ActiveDirectory
  //        is typically 10x faster.
  var opts = _.defaults(opts || {}, {
    filter: '(member='+parseDistinguishedName(dn)+')',
    scope: 'sub',
    attributes: [ 'objectCategory', 'groupType', 'distinguishedName', 'cn' ]
  });
  search.call(self, opts, function(err, results) {
    if (err) {
      if (callback) callback(err);
      return;
    }

    var groups = [];

    async.forEach(results, function(group, asyncCallback) {
      // accumulates discovered groups
      if (typeof(stack) !== 'undefined') {
        if (!_.findWhere(stack, { cn: group.cn })) {
          stack.push(new Group({ dn: group.dn, cn: group.cn }));
        } else {
          // ignore groups already found
          return asyncCallback();
        }

        _.each(stack,function(s) {
          if (!_.findWhere(groups, { cn: s.cn })) {
            groups.push(s);
          }
        });
      }

      groups.push(new Group({ dn: group.dn, cn: group.cn }));

      // http://msdn.microsoft.com/en-us/library/windows/desktop/ms675935(v=vs.85).aspx
      // 0 = Not A Group
      if (parseInt(group.groupType)) {
        // Get the groups that this group may be a member of.
        getGroupMembershipForDN.call(self, group.dn, groups, function(err, nestedGroups) {					
          if (err) {
            if (asyncCallback) asyncCallback(err);
            return;
          }

          groups.push.apply(groups, _.map(nestedGroups, function(nestedGroup) {
            return(new Group({ dn: nestedGroup.dn, cn: nestedGroup.cn }));
          }));
          if (asyncCallback) asyncCallback(err);
        });
      }
      else asyncCallback();
    }, function(err) {
       if (err) {
        if (callback) callback(err);
        return;
      }

      // Remove the duplicates from the list.
      if (callback) {
        callback(err, _.uniq(groups, function(group) {
          return(group.dn);
        }));
      }
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
  if (typeof(opts) == 'string') {
    filter = opts;
    opts = undefined;
  }
  
  var opts = _.defaults(opts || {}, {
    filter: filter,
    scope: 'sub',
    attributes: [ 'distinguishedName' ]
  });
  search.call(self, opts, function(err, results) {
    if (err) {
      if (callback) callback(err);
      return;
    }
 
    if (callback) {
      // Extract just the DN from the results
      callback(null, _.map(results, function(result) {
        return(result.dn);
      }));
    }
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

  // Already a dn?
  if (isDistinguishedName.call(self, username)) {
    callback(null, username);
    return;
  }

  getDistinguishedNames.call(self, opts, getUserQueryFilter(username), function(err, dns) {
    if (err) {
      if (callback) callback(err);
      return;
    }

    if (callback) {
      callback(null, (dns || [])[0]);
    }
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

  // Already a dn?
  if (isDistinguishedName.call(self, groupName)) {
    callback(null, groupName);
    return;
  }

  getDistinguishedNames.call(self, opts, getGroupQueryFilter(groupName), function(err, dns) {
    if (err) {
      if (callback) callback(err);
      return;
    }

    if (callback) callback(null, (dns || [])[0]);
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
  var self = this;

  // Check to see if any of the result attributes have range= attributes. 
  // If not, return immediately.
  if (! RangeRetrievalSpecifierAttribute.prototype.hasRangeAttributes(result)) {
    callback(null, result);
    return;
  }

  // Prase the range attributes that were provided. If the range attributes are null
  // or indicate that the range is complete, return the result.
  var rangeAttributes = RangeRetrievalSpecifierAttribute.prototype.getRangeAttributes(result);
  if ((! rangeAttributes) || (rangeAttributes.length <= 0)) {
    callback(null, result);
    return;
  }

  // Parse each of the range attributes. Merge the range attributes into
  // the properly named property.
  var queryAttributes = [];
  _.each(rangeAttributes, function(rangeAttribute) {
    // Merge existing range into the properly named property.
    result[rangeAttribute.attributeName].push.apply(result[rangeAttribute.attributeName], result[rangeAttribute.toString()]);
    delete(result[rangeAttribute.toString()]);

    // Build our ldap query attributes with the proper attribute;range= tags to
    // get the next sequence of data.
    var queryAttribute = rangeAttribute.next();
    if (queryAttribute) {
      queryAttributes.push(queryAttribute.toString());
    }
  });

  // If we're at the end of the range (i.e. all items retrieved), return the result.
  if (queryAttributes.length <= 0) {
    callback(null, result);
    return;
  }

  // Execute the query again with the query attributes updated.      
  opts = _.defaults({ attributes: queryAttributes }, opts);
  search.call(self, opts, function onSearch(err, results) {
    if (err) {
      if (callback) callback(err);
      return;
    }

    // Parse any range attributes if they are specified.
    var rangeResult = (results || [])[0];
    if (RangeRetrievalSpecifierAttribute.prototype.hasRangeAttributes(rangeResult)) {
      // Append the attributes from the range to the original result. Then
      // call the parseRangeAttributes function again.
      for(var key in rangeResult) {
        result[key] = rangeResult[key];
      }
      parseRangeAttributes.call(self, result, opts, callback);
    }
    else {
      callback(null, result);
      return;
    }
  });
}

/**
 * For the specified group, retrieve all of the users that belong to the group.
 *
 * @public
 * @param {Object} [opts] Optional LDAP query string parameters to execute. { scope: '', filter: '', attributes: [ '', '', ... ], sizeLimit: 0, timelimit: 0 }
 * @param {String} groupName The name of the group to retrieve membership from.
 * @param {Function} callback The callback to execute when completed. callback(err: {Object}, groups: {Array[User]})
 */
ActiveDirectory.prototype.getUsersForGroup = function getUsersForGroup(opts, groupName, callback) {
  var self = this;

  if (typeof(groupName) === 'function') {
    callback = groupName;
    groupName = opts;
    opts = undefined;
  }

  var users = [];
  self.findGroup(opts, groupName, function(err, group) {
    if (err) {
      if (callback) callback(err);
      return;
    }

    // Group not found
    if (! group) {
      callback(null, group);
      return;
    }

    var users = [];
    // We're going to build up a bulk LDAP query so we can reduce
    // the number of round trips to the server. We need to get
    // additional details about each 'member' to determine if 
    // it is a group or another user. If it's a group, we need
    // to recursively retrieve the members of that group.
    var filter = _.reduce(group.member || [], function(memo, member, index) {
      return(memo+'(distinguishedName='+parseDistinguishedName(member)+')');
    }, '');
    filter = '(&(|(objectCategory=User)(objectCategory=Group))(|'+filter+'))';

    var opts = {
      filter: filter,
      scope: 'sub',
      attributes: defaultAttributes.user.concat([ 'groupType' ])
    };
    search.call(self, opts, function onSearch(err, members) {
      if (err) {
        if (callback) callback(err);
        return;
      }  

      // Parse the results in parallel.
      async.forEach(members, function(member, asyncCallback) {
        // If a user, no groupType will be specified.
        if (! member.groupType) {
          users.push(new User(member));
          asyncCallback();
        }
        else {
          // We have a group, recursively get the users belonging to this group.
          self.getUsersForGroup(member.cn, function(err, nestedUsers) {
            users.push.apply(users, nestedUsers);
            asyncCallback();
          });
        }
      }, function(err) {
        if (callback) {
          // Remove duplicates
          callback(null, _.uniq(users, function(user) {
            return(user.dn);
          }));
        }
      });
    });
  });
}

/**
 * For the specified username, get all of the groups that the user is a member of.
 *
 * @public
 * @param {Object} [opts] Optional LDAP query string parameters to execute. { scope: '', filter: '', attributes: [ '', '', ... ], sizeLimit: 0, timelimit: 0 }
 * @param {String} username The username to retrieve membership information about.
 * @param {Function} callback The callback to execute when completed. callback(err: {Object}, groups: {Array[Group]})
 */
ActiveDirectory.prototype.getGroupMembershipForUser = function getGroupMembershipForUser(opts, username, callback) {
  var self = this;

  if (typeof(username) === 'function') {
    callback = username;
    username = opts;
    opts = undefined;
  }

  getUserDistinguishedName.call(self, opts, username, function(err, dn) {
    if (err) {
      if (callback) callback(err);
      return;
    }  

    if (! dn) {
      if (callback) callback();
      return;
    }
    getGroupMembershipForDN.call(self, opts, dn, callback);
  });
};

/**
 * For the specified group, get all of the groups that the group is a member of.
 *
 * @public
 * @param {Object} [opts] Optional LDAP query string parameters to execute. { scope: '', filter: '', attributes: [ '', '', ... ], sizeLimit: 0, timelimit: 0 }
 * @param {String} groupName The group to retrieve membership information about.
 * @param {Function} callback The callback to execute when completed. callback(err: {Object}, groups: {Array[Group]})
 */
ActiveDirectory.prototype.getGroupMembershipForGroup = function getGroupMembershipForGroup(opts, groupName, callback) {
  var self = this;
  
  if (typeof(groupName) === 'function') {
    callback = groupName;
    groupName = opts;
    opts = undefined;
  }

  getGroupDistinguishedName.call(self, opts, groupName, function(err, dn) {
    if (err) {
      if (callback) callback(err);
      return;
    }  

    if (! dn) {
      if (callback) callback();
      return;
    }
    getGroupMembershipForDN.call(self, opts, dn, callback);
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

  self.findUser(opts, username, function(err, user) {
    if (err) {
      if (callback) callback(err);
      return;
    }

    if (callback) callback(null, user != null);
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
  self.findGroup(opts, groupName, function(err, result) {
    if (err) {
      if (callback) callback(err);
      return;
    }

    if (callback) callback(null, result != null);
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

  self.getGroupMembershipForUser(opts, username, function(err, groups) {
    if (err) {
      if (callback) callback(err);
      return;
    }
    if ((! groups) || (groups.length == 0)) {
      if (callback) callback(null, false);
      return;
    }

    if (callback) {
      // Check to see if the group.distinguishedName or group.cn matches the list of 
      // retrieved groups.
      callback(null, _.any(groups, function(item) {
        return(((item.dn || '').toLowerCase() === (groupName || '').toLowerCase()) ||
               ((item.cn || '').toLowerCase() === (groupName || '').toLowerCase()));
              
      }));
    }
  });
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

  var opts = _.defaults(opts || {}, {
    filter: getGroupQueryFilter.call(self, groupName),
    scope: 'sub',
    attributes: defaultAttributes.group
  });
  search.call(self, opts, function onSearch(err, results) {
    if (err) {
      if (callback) callback(err);
      return;
    }

    if ((! results) || (results.length == 0)) {
      if (callback) callback();
      return;
    }

    // Member can contain a range= attribute. Special processing 
    // (paging) required to get all values. Essentially the query needs to
    // be executed multiple times to get all of the values.
    parseRangeAttributes.call(self, results[0], opts, function(err, result) {
      if (err) {
        if (callback) callback(err);
        return;
      }

      var group = new Group(result);
      self.emit('group', group);
      if (callback) callback(null, group);
    });
  });
};

/**
 * Retrieves the specified user.
 *
 * @public
 * @param {Object} [opts] Optional LDAP query string parameters to execute. { scope: '', filter: '', attributes: [ '', '', ... ], sizeLimit: 0, timelimit: 0 }
 * @param {String} username The username to retrieve information about. Optionally can pass in the distinguishedName (dn) of the user to retrieve.
 * @param {Boolean} [includeMembership] Indicates if the request should also retrieve the group memberships for the user. Default = false;
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

  var opts = _.defaults(opts || {}, {
    filter: getUserQueryFilter.call(self, username),
    scope: 'sub',
    attributes: defaultAttributes.user
  });
  search.call(self, opts, function onSearch(err, results) {
    if (err) {
      if (callback) callback(err);
      return;
    }

    if ((! results) || (results.length == 0)) {
      if (callback) callback();
      return;
    }

    var user = new User(results[0]);
    // Also retrieving user group memberships?
    if (includeMembership) {
      getGroupMembershipForDN.call(self, user.dn, function(err, groups) {
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
 * Attempts to authenticate the specified username / password combination.
 *
 * @public
 * @param {String} username The username to authenticate.
 * @param {String} password The password to use for authentication.	
 * @param {Function} callback The callback to execute when the authenication is completed. callback(err: {Object}, authenticated: {Boolean})
 */
ActiveDirectory.prototype.authenticate = function authenticate(username, password, callback) {
  var self = this;

  // Skip authentication if an empty username or password is provided.
  if ((! username) || (! password)) {
    if (callback) {
      var err = {
        'code': 0x31,
        'errno': 'LDAP_INVALID_CREDENTIALS',
        'description': 'The supplied credential is invalid'
      };
      callback(err, false);
    }
    return;
  }

  var client = createClient.call(self);
  client.on('error', function(err) {
    // Ignore ECONNRESET errors
    if ((err || {}).errno !== 'ECONNRESET') {
      self.emit('error', err);
    }
  });
  client.bind(username, password, function(err, result) {
    client.unbind();
    if (err) {
      if (callback) callback(err, false);
      return;
    }

    if (callback) callback(err, true);
  });
};

module.exports = ActiveDirectory;
