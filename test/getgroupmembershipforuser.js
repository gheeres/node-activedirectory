var _ = require('underscore');
var assert = require('./assert.more');
var ActiveDirectory = require('../index');
var config = require('./config');

describe('ActiveDirectory', function() {
  var ad;
  var settings = require('./settings').getGroupMembershipForUser;

  before(function() {
   ad = new ActiveDirectory(config);
  });

  describe('#getGroupMembershipForUser()', function() {
    settings.users.forEach(function(user) {
      ['dn', 'userPrincipalName', 'sAMAccountName'].forEach(function(usernameAttribute) {
        it('should return ' + (user.members || []).length + ' groups for (' + usernameAttribute + ') ' + user[usernameAttribute], function(done) {
          ad.getGroupMembershipForUser(user[usernameAttribute], function(err, groups) {
            if (err) return(done(err));

            assert.equalDifference(user.members || [], groups || []);
//            assert.equal((user.members || []).length, (groups || []).length);
//
//            (user.members || []).forEach(function(source) {
//              var lowerCaseSource = (source || '').toLowerCase();
//              assert(_.any(groups, function(result) {
//                return((result.cn || '').toLowerCase()=== lowerCaseSource);
//              }));
//            });
            done();
          });
        });
      });
    });
    it('should return empty groups if groupName doesn\'t exist', function(done) {
      ad.getGroupMembershipForUser('!!!NON-EXISTENT GROUP!!!', function(err, groups) {
        if (err) return(done(err));

        assert(! groups);
        done();
      });
    });
    it('should return default group attributes when not specified', function(done) {
      var defaultAttributes = [ 'objectCategory', 'distinguishedName', 'cn', 'description' ];
      var user = settings.users[0];
      ad.getGroupMembershipForUser(user.userPrincipalName, function(err, groups) {
        if (err) return(done(err));
        assert(groups);

        (groups || []).forEach(function(group) {
          assert(_.keys(group || {}).length <= defaultAttributes.length);
        });
        done();
      });
    });
  });

  describe('#getGroupMembershipForUser(opts)', function() {
    it('should return only requested attributes', function(done) {
      var opts = {
        attributes: [ 'createTimeStamp' ]
      };
      var user = settings.users[0];
      ad.getGroupMembershipForUser(opts, user.userPrincipalName, function(err, groups) {
        if (err) return(done(err));
        assert(groups);

        assert.equal((user.members || []).length, (groups || []).length);
        (groups || []).forEach(function(group) {
          var keys = _.keys(group) || [];
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

