var _ = require('underscore');
var assert = require('assert');
var ActiveDirectory = require('../index');
var config = require('./config');

describe('ActiveDirectory', function() {
  var ad;
  var settings = require('./settings').getUsersForGroup;

  before(function() {
    ad = new ActiveDirectory(config);
  });

  describe('#getUsersForGroup()', function() {
    settings.groups.forEach(function(group) {
     it('should return ' + (group.users || []).length + ' users for (distinguishedName) ' + group.dn, function(done) {
        ad.getUsersForGroup(group.dn, function(err, users) {
          if (err) return(done(err));
          assert(users);
          assert.equal((group.users || []).length, (users || []).length);

          (group.users || []).forEach(function(source) {
            var lowerCaseSource = (source || '').toLowerCase();
            assert(_.any(users, function(result) {
              return((result.dn || '').toLowerCase()=== lowerCaseSource);
            }));
          });
          done();
        });
     }); 
     it('should return ' + (group.users || []).length + ' users for (commonName) ' + group.cn, function(done) {
        ad.getUsersForGroup(group.cn, function(err, users) {
          if (err) return(done(err));
          assert(users);
          assert.equal((group.users || []).length, (users || []).length);

          (group.users || []).forEach(function(source) {
            var lowerCaseSource = (source || '').toLowerCase();
            assert(_.any(users, function(result) {
              return((result.dn || '').toLowerCase()=== lowerCaseSource);
            }));
          });
          done();
        });
     }); 
   });
    it('should return empty users if groupName doesn\'t exist', function(done) {
      ad.getUsersForGroup('!!!NON-EXISTENT GROUP!!!', function(err, users) {
        if (err) return(done(err));
        assert(! users);
        done();
      });
    });
    it('should return default user attributes when not specified', function(done) {
      var defaultAttributes = [ 
        'userPrincipalName', 'sAMAccountName', 'mail',
        'lockoutTime', 'whenCreated', 'pwdLastSet', 'userAccountControl',
        'employeeID', 'sn', 'givenName', 'initials', 'cn', 'displayName',
        'comment', 'description' 
      ];
      var group = settings.groups[0];
      ad.getUsersForGroup(group.dn, function(err, users) {
        if (err) return(done(err));
        assert(users);
        (users || []).forEach(function(user) {
          assert(_.keys(user || {}).length <= defaultAttributes.length);
        });
        done();
      });
    });
  });

  describe('#getUsersForGroup(opts)', function() {
    it('should return only requested attributes', function(done) {
      var opts = {
        attributes: [ 'createTimeStamp' ]
      };
      var group = settings.groups[0];
      ad.getUsersForGroup(opts, group.dn, function(err, users) {
        if (err) return(done(err));
        assert(users);
        assert.equal((group.users || []).length, (users || []).length);
        (users || []).forEach(function(user) {
          var keys = _.keys(user) || [];
          assert(keys.length <= opts.attributes.length);
          keys.forEach(function(key) {
           assert(_.any(opts.attributes, function(attribute) {
              return(key === attribute);
            }));
          });
        });
        done();
      });
    });
  });
});

