var _ = require('underscore');
var assert = require('assert');
var ActiveDirectory = require('../index');
var config = require('./config');

describe('ActiveDirectory', function() {
  var ad;
  var settings = require('./settings').getGroupMembershipForGroup;

  before(function() {
    ad = new ActiveDirectory(config);
  });

  describe('#getGroupMembershipForGroup()', function() {
    it('should return groups if groupName (distinguishedName) is valid', function(done) {
      var verified = 0;
      settings.groups.forEach(function(group) {
        ad.getGroupMembershipForGroup(group.dn, function(err, groups) {
          if (err) return(done(err));
          assert.equal((group.members || []).length, (groups || []).length);
          // Validate membership equality
          (groups.members || []).forEach(function(source) {
            var lowerCaseSource = (source || '').toLowerCase();
            assert(_.any(groups, function(result) {
              return((result.cn || '').toLowerCase()=== lowerCaseSource);
            }));
          });
          if (++verified === settings.groups.length) done();
        });
      });
    });
    it('should return groups if groupName (commonName) exists', function(done) {
      var verified = 0;
      settings.groups.forEach(function(group) {
        ad.getGroupMembershipForGroup(group.cn, function(err, groups) {
          if (err) return(done(err));
          assert.equal((group.members || []).length, (groups || []).length);
          // Validate membership equality
          (groups.members || []).forEach(function(source) {
            var lowerCaseSource = (source || '').toLowerCase();
            assert(_.any(groups, function(result) {
              return((result.cn || '').toLowerCase()=== lowerCaseSource);
            }));
          });
          if (++verified === settings.groups.length) done();
        });
      });
    });
    it('should return empty groups if groupName doesn\'t exist', function(done) {
      ad.getGroupMembershipForGroup('!!!NON-EXISTENT GROUP!!!', function(err, groups) {
        if (err) return(done(err));
        assert(! groups);
        done();
      });
    });
    it('should return default group attributes when not specified', function(done) {
      var defaultAttributes = [ 'objectCategory', 'distinguishedName', 'cn', 'description' ];
      ad.getGroupMembershipForGroup(settings.groups[0].dn, function(err, groups) {
        if (err) return(done(err));
        assert(groups);
        (groups || []).forEach(function(group) {
          assert(_.keys(group || {}).length <= defaultAttributes.length);
        });
        done();
      });
    });
  });

  describe('#getGroupMembershipForGroup(opts)', function() {
    it('should return only requested attributes', function(done) {
      var opts = {
        attributes: [ 'createTimeStamp' ]
      };
      ad.getGroupMembershipForGroup(opts, settings.groups[0].dn, function(err, groups) {
        if (err) return(done(err));
        assert(groups);
        assert.equal((settings.groups[0].members || []).length, (groups || []).length);
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

