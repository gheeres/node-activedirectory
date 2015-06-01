var assert = require('assert');
var _ = require('underscore');
var ActiveDirectory = require('../index');
var config = require('./config');

describe('ActiveDirectory', function() {
  var ad;
  var settings = require('./settings').findUsers;
  var timeout = 6000; // The timeout in milliseconds before a test is considered failed. 

  before(function() {
   ad = new ActiveDirectory(config);
  });

  describe('#findUsers()', function() {
    settings.users.forEach(function(user) {
      it('should return ' + (user.results || []).length + ' users for query \'' + JSON.stringify(user.query) + '\'', function(done) {
        this.timeout(timeout);

        ad.findUsers(user.query, function(err, users) {
          if (err) return(done(err));
          assert(users || ((user.results || []).length === (users || []).length));

          assert.equal((user.results || []).length, (users || []).length);
          (user.results || []).forEach(function(expectedUser) {
            var lowerCaseExpectedUser = (expectedUser || '').toLowerCase();
            assert(_.any(users || [], function(result) {
              return(lowerCaseExpectedUser === (result.cn || '').toLowerCase());
            }));
          });
          done();
        });
      });
    });
    it('should return default user attributes when not specified', function(done) {
      var defaultAttributes = [ 
        'dn',
        'userPrincipalName', 'sAMAccountName', 'mail',
        'lockoutTime', 'whenCreated', 'pwdLastSet', 'userAccountControl',
        'employeeID', 'sn', 'givenName', 'initials', 'cn', 'displayName',
        'comment', 'description' ];
      var user = settings.users[0];
      ad.findUsers(user.query, function(err, users) {
        if (err) return(done(err));
        assert(users);

        (users || []).forEach(function(user) {
          var attributes = _.keys(user) || [];
          assert(attributes.length <= defaultAttributes.length);
          attributes.forEach(function(attribute) {
            var lowerCaseAttribute = (attribute || '').toLowerCase();
            assert(_.any(defaultAttributes, function(defaultAttribute) {
              return(lowerCaseAttribute === (defaultAttribute || '').toLowerCase());
            }));
          });
        });
        done();
      });
    });
  });

  describe('#findUsers(opts)', function() {
    it('should include groups/membership if opts.includeMembership[] = [ \'all\' ]', function(done) {
      this.timeout(timeout);

      var user = settings.users[0];
      var opts = {
        includeMembership: [ 'all' ],
        filter: user.query
      };
      ad.findUsers(opts, function(err, users) {
        if (err) return(done(err));
        assert(users);

        // Not verifying actual group results, just verifying that groups attribute
        // exists.
        assert(_.any(users || [], function(user) {
          return(user.groups);
        }));
        done();
      });
    });
    it('should include groups/membership if opts.includeMembership[] = [ \'user\' ]', function(done) {
      this.timeout(timeout);

      var user = settings.users[0];
      var opts = {
        includeMembership: [ 'user' ],
        filter: user.query
      };
      ad.findUsers(opts, function(err, users) {
        if (err) return(done(err));
        assert(users);

        // Not verifying actual group results, just verifying that groups attribute
        // exists. Not all users may have groups.
        assert(_.any(users || [], function(user) {
          return(user.groups);
        }));
        done();
      });
    });
    it('should not include groups/membership if opts.includeMembership disabled', function(done) {
      var user = settings.users[0];
      var opts = {
        includeMembership: false,
        filter: user.query
      };
      ad.findUsers(opts, function(err, users) {
        if (err) return(done(err));
        assert(users);

        // Not verifying actual group results, just verifying that groups attribute
        // exists.
        assert(_.all(users || [], function(user) {
          return(! user.group);
        }));
        done();
      });
    });
    it('should return only requested attributes', function(done) {
      var user = settings.users[0];
      var opts = {
        attributes: [ 'cn' ],
        filter: user.query
      };
      ad.findUsers(opts, function(err, users) {
        if (err) return(done(err));
        assert(users);

        (users || []).forEach(function(user) {
          var keys = _.keys(user) || [];
          assert(keys.length <= opts.attributes.length);
          if (keys.length === opts.attributes.length) {
            assert(_.any(opts.attributes, function(attribute) {
              return(_.any(keys, function(key) {
                return(key === attribute);
              }));
            }));
          }
        });
        done();
      });
    });
  });
});

