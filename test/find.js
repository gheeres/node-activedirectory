var assert = require('assert');
var _ = require('underscore');
var ActiveDirectory = require('../index');
var config = require('./config');

describe('ActiveDirectory', function() {
  var ad;
  var settings = require('./settings').find;
  var timeout = 6000; // The timeout in milliseconds before a test is considered failed. 

  before(function() {
   ad = new ActiveDirectory(config);
  });

  describe('#find()', function() {
    settings.queries.forEach(function(query) {
      it('should return ' + ((query.results || []).users || []).length + ' users, ' + 
                            ((query.results || []).groups|| []).length + ' groups, ' +
                            ((query.results || []).other || []).length + ' other ' +
                            'for query \'' + JSON.stringify(query.query) + '\'', function(done) {
        this.timeout(timeout);

        ad.find(query.query, function(err, results) {
          if (err) return(done(err));
          assert(results);

          ['users', 'groups', 'other'].forEach(function(key) {
            var expectedResults = ((query.results || [])[key] || []);
            var actualResults = ((results || [])[key] || []);

            assert.equal(expectedResults.length, actualResults.length,
                         'Only ' + actualResults.length + ' ' + key + ' retrieved. ' +
                         'Expected: ' + JSON.stringify(expectedResults) + '; ' +
                         'Actual: ' + JSON.stringify(_.map(actualResults || [], function(item) { return(item.cn); })));
            (expectedResults || []).forEach(function(expectedResult) {
              var lowerCaseExpectedResult = (expectedResult || '').toLowerCase();
              assert(_.any(actualResults || [], function(result) {
                return(lowerCaseExpectedResult === (result.cn || '').toLowerCase());
              }), 'Expected ' + key + ' result ' + expectedResult + ' not found in list of results: ' + JSON.stringify(actualResults));
            });
          });
          done();
        });
      });
    });
    it('should return default query attributes when not specified', function(done) {
      var defaultAttributes = {
        groups : [ 'dn', 'objectCategory', 'cn', 'description' ],
        users: [ 
          'dn',
          'userPrincipalName', 'sAMAccountName', 'mail',
          'lockoutTime', 'whenCreated', 'pwdLastSet', 'userAccountControl',
          'employeeID', 'sn', 'givenName', 'initials', 'cn', 'displayName',
          'comment', 'description' 
        ],
      };
      defaultAttributes.other = _.union(defaultAttributes.groups, defaultAttributes.users);

      var query = settings.queries[0];
      ad.find(query.query, function(err, results) {
        if (err) return(done(err));
        assert(results);

        ['users', 'groups', 'other'].forEach(function(key) {
          var keyAttributes = defaultAttributes[key] || [];
          ((results || [])[key] || []).forEach(function(result) {
            var attributes = _.keys(result || {}) || [];
            assert(attributes.length <= keyAttributes.length);
            attributes.forEach(function(attribute) {
              var lowerCaseAttribute = (attribute || '').toLowerCase();
              assert(_.any(keyAttributes, function(defaultAttribute) {
                return(lowerCaseAttribute === (defaultAttribute || '').toLowerCase());
              }));
            });
          });
        });
        done();
      });
    });
  });
  describe('#find(opts)', function() {
    it('should include groups/membership groups and users if opts.includeMembership[] = [ \'all\' ]', function(done) {
      this.timeout(timeout);

      var query = settings.queries[0];
      var opts = {
        includeMembership: [ 'all' ],
        filter: query.query
      };
      ad.find(opts, function(err, results) {
        if (err) return(done(err));
        assert(results);

        // Not verifying actual group results, just verifying 
        // that groups attribute exists for groups and users results.
        // Others should NOT have groups.
        ['users', 'groups', 'other'].forEach(function(key) {
          var items = (results || {})[key] || [];
          assert(_.any(items || [], function(item) {
            return((key === 'other') ? (! item.groups) : item.groups);
          }));
        });
        done();
      });
    });
    it('should include groups/membership for groups if opts.includeMembership[] = [ \'group\' ]', function(done) {
      this.timeout(timeout);

      var query = settings.queries[0];
      var opts = {
        includeMembership: [ 'group' ],
        filter: query.query
      };
      ad.find(opts, function(err, results) {
        if (err) return(done(err));
        assert(results);

        // Not verifying actual group results, just verifying 
        // that groups attribute exists for group results. 
        // Users and others should NOT have groups.
        ['users', 'groups', 'other'].forEach(function(key) {
          var items = (results || {})[key] || [];
          assert(_.any(items || [], function(item) {
            return((key === 'groups') ? item.groups : (! item.groups));
          }));
        });
        done();
      });
    });
    it('should include groups/membership for users if opts.includeMembership[] = [ \'user\' ]', function(done) {
      this.timeout(timeout);

      var query = settings.queries[0];
      var opts = {
        includeMembership: [ 'user' ],
        filter: query.query
      };
      ad.find(opts, function(err, results) {
        if (err) return(done(err));
        assert(results);

        // Not verifying actual group results, just verifying 
        // that groups attribute exists for groups and users results.
        // Groups and others should NOT have groups.
        ['users', 'groups', 'other'].forEach(function(key) {
          var items = (results || {})[key] || [];
          assert(_.any(items || [], function(item) {
            return((key === 'users') ? item.groups : (! item.groups));
          }));
        });
        done();
      });
    });
    it('should not include groups/membership if opts.includeMembership disabled', function(done) {
      var query = settings.queries[0];
      var opts = {
        includeMembership: false,
        filter: query.query
      };
      ad.find(opts, function(err, results) {
        if (err) return(done(err));
        assert(results);

        // Not verifying actual group results, just verifying 
        // that groups attribute does NOT exist.
        ['users', 'groups', 'other'].forEach(function(key) {
          var items = (results || {})[key] || [];
          assert(_.all(items || [], function(item) {
            return(! item.groups);
          }));
        });
        done();
      });
    });
    it('should return only requested attributes', function(done) {
      this.timeout(timeout);
      var query = settings.queries[0];
      var opts = {
        attributes: [ 'cn' ],
        filter: query.query
      };
      ad.find(opts, function(err, results) {
        if (err) return(done(err));
        assert(results);

        ['users', 'groups', 'other'].forEach(function(key) {
          var actualResults = (results || {})[key] || [];
          (actualResults || []).forEach(function(result) {
            var keys = _.keys(result) || [];
            assert(keys.length <= opts.attributes.length);
            if (keys.length === opts.attributes.length) {
              assert(_.any(opts.attributes, function(attribute) {
                return(_.any(keys, function(key) {
                  return(key === attribute);
                }));
              }));
            }
          });
        });
        done();
      });
    });
  });
});

