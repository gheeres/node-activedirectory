var _ = require('underscore');
var assert = require('./assert.more');
var ActiveDirectory = require('../index');
var config = require('./config');

describe('ActiveDirectory', function() {
  var ad;
  var settings = require('./settings').getGroupMembershipForGroup;

  before(function() {
    ad = new ActiveDirectory(config);
  });

  describe('#getGroupMembershipForGroup()', function() {
    settings.groups.forEach(function(group) {
      ['dn', 'cn'].forEach(function(groupAttribute) {
        it('should return ' + (group.members || []).length + ' groups for (' + groupAttribute + ') ' + group[groupAttribute], function(done) {
          ad.getGroupMembershipForGroup(group[groupAttribute], function(err, groups) {
            if (err) return(done(err));

            assert.equalDifference(group.members || [], groups || []);
            done();
          });
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
      var defaultAttributes = [ 'dn', 'objectCategory', 'cn', 'description' ];
      var group = settings.groups[0];
      ad.getGroupMembershipForGroup(group.dn, function(err, groups) {
        if (err) return(done(err));
        assert(groups);
        (groups || []).forEach(function(item) {
          assert(_.keys(item || {}).length <= defaultAttributes.length);
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
      var group = settings.groups[0];
      ad.getGroupMembershipForGroup(opts, group.dn, function(err, groups) {
        if (err) return(done(err));
        assert(groups);
        assert.equal((group.members || []).length, (groups || []).length);
        (groups || []).forEach(function(item) {
          var keys = _.keys(item) || [];
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

