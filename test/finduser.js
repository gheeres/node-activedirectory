var assert = require('assert');
var _ = require('underscore');
var ActiveDirectory = require('../index');
var config = require('./config');

describe('ActiveDirectory', function() {
  var ad;
  var settings = require('./settings').findUser;

  before(function() {
   ad = new ActiveDirectory(config);
  });

  describe('#findUser()', function() {
    [ 'userPrincipalName', 'sAMAccountName', 'dn' ].forEach(function(userAttribute) {
      it('should return user for (' + userAttribute + ') ' + settings.username[userAttribute], function(done) {
        ad.findUser(settings.username[userAttribute], function(err, user) {
          if (err) return(done(err));
          assert(user);
          done();
        });
      });
    });
    it('should return undefined if the username doesn\'t exist', function(done) {
      ad.findUser('!!!NON-EXISTENT USER!!!', function(err, user) {
        if (err) return(done(err));
        assert(! user);
        done();
      });
    });
    it('should return default user attributes when not specified', function(done) {
      var defaultAttributes = [ 
        'dn', 'distinguishedName',
        'userPrincipalName', 'sAMAccountName', /*'objectSID',*/ 'mail',
        'lockoutTime', 'whenCreated', 'pwdLastSet', 'userAccountControl',
        'employeeID', 'sn', 'givenName', 'initials', 'cn', 'displayName',
        'comment', 'description' 
      ];
      ad.findUser(settings.username.userPrincipalName, function(err, user) {
        if (err) return(done(err));
        assert(user);

        var attributes = _.keys(user) || [];
        assert(attributes.length <= defaultAttributes.length);
        attributes.forEach(function(attribute) {
          var lowerCaseAttribute = (attribute || '').toLowerCase();
          assert(_.any(defaultAttributes, function(defaultAttribute) {
            return(lowerCaseAttribute === (defaultAttribute || '').toLowerCase());
          }));
        });
        done();
      });
    });
  });
  
  describe('#findUser(opts)', function() {
    it('should use the custom opts.filter if provided', function(done) {
      var opts = {
        filter: settings.opts.custom
      };
      ad.findUser(opts, settings.username.userPrincipalName, function(err, user) {
        if (err) return(done(err));
        assert(user);
        assert((settings.username.userPrincipalName || '').toLowerCase() !== (user.userPrincipalName || '').toLowerCase());
        done();
      });
    });
    it('should include groups/membership if opts.includeMembership[] = [ \'all\' ]', function(done) {
      var opts = {
        includeMembership: [ 'all' ]
      };
      ad.findUser(opts, settings.username.userPrincipalName, function(err, user) {
        if (err) return(done(err));
        assert(user);
        assert.equal((settings.groups || []).length, (user.groups || []).length);
        done();
      });
    });
    it('should include groups/membership if opts.includeMembership[] = [ \'user\' ]', function(done) {
      var opts = {
        includeMembership: [ 'user' ]
      };
      ad.findUser(opts, settings.username.userPrincipalName, function(err, user) {
        if (err) return(done(err));
        assert(user);
        assert.equal((settings.groups || []).length, (user.groups || []).length);
        done();
      });
    });
    it('should return expected groups/membership if opts.includeMembership enabled', function(done) {
      var opts = {
        includeMembership: [ 'user', 'all' ]
      };
      ad.findUser(opts, settings.username.userPrincipalName, function(err, user) {
        if (err) return(done(err));
        assert(user);
        assert.equal((settings.groups || []).length, (user.groups || []).length);
        (user.groups || []).forEach(function(group) {
          var lowercaseGroup = (group.cn || '').toLowerCase();
          assert(_.any(settings.groups || [], function(expectedGroup) {
            return(lowercaseGroup === expectedGroup.toLowerCase());
          }));
        });
        done();
      });
    });
    it('should return only the first user if more than one result returned', function(done) {
      var opts = {
        filter: settings.opts.multipleFilter
      };
      ad.findUser(opts, '' /* ignored since we're setting our own filter */, function(err, user) {
        if (err) return(done(err));
        assert(user);
        assert(! _.isArray(user));
        done();
      });
    });
    it('should return only requested attributes', function(done) {
      var opts = {
        attributes: [ 'cn' ]
      };
      ad.findUser(opts, settings.username.userPrincipalName, function(err, user) {
        if (err) return(done(err));
        assert(user);

        var keys = _.keys(user) || [];
        assert(keys.length <= opts.attributes.length);
        if (keys.length === opts.attributes.length) {
          assert(_.any(opts.attributes, function(attribute) {
            return(_.any(keys, function(key) {
              return(key === attribute);
            }));
          }));
        }
        done();
      });
    });
  });
});

