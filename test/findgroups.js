var assert = require('assert');
var _ = require('underscore');
var ActiveDirectory = require('../index');
var config = require('./config');

describe('ActiveDirectory', function() {
  var ad;
  var settings = require('./settings').findGroups;
  var timeout = 6000; // The timeout in milliseconds before a test is considered failed. 

  before(function() {
   ad = new ActiveDirectory(config);
  });

  describe('#findGroups()', function() {
    settings.groups.forEach(function(group) {
      it('should return ' + (group.results || []).length + ' groups for query \'' + JSON.stringify(group.query) + '\'', function(done) {
        this.timeout(timeout);

        ad.findGroups(group.query, function(err, groups) {
          if (err) return(done(err));
          assert(groups || ((group.results || []).length === (groups || []).length));

          assert.equal((group.results || []).length, (groups || []).length);
          (group.results || []).forEach(function(expectedGroup) {
            var lowerCaseExpectedGroup = (expectedGroup || '').toLowerCase();
            assert(_.any(groups || [], function(result) {
              return(lowerCaseExpectedGroup === (result.cn || '').toLowerCase());
            }));
          });
          done();
        });
      });
    });
    it('should return default group attributes when not specified', function(done) {
      var defaultAttributes = [ 'dn', 'objectCategory', 'cn', 'description' ];
      var group = settings.groups[0];
      ad.findGroups(group.query, function(err, groups) {
        if (err) return(done(err));
        assert(groups);

        (groups || []).forEach(function(group) {
          var attributes = _.keys(group) || [];
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

  describe('#findGroups(opts)', function() {
    it('should include groups/membership if opts.includeMembership[] = [ \'all\' ]', function(done) {
      this.timeout(timeout);

      var group = settings.groups[0];
      var opts = {
        includeMembership: [ 'all' ],
        filter: group.query
      };
      ad.findGroups(opts, function(err, groups) {
        if (err) return(done(err));
        assert(groups);

        // Not verifying actual group results, just verifying that groups attribute
        // exists.
        assert(_.any(groups || [], function(group) {
          return(group.groups);
        }));
        done();
      });
    });
    it('should include groups/membership if opts.includeMembership[] = [ \'group\' ]', function(done) {
      this.timeout(timeout);

      var group = settings.groups[0];
      var opts = {
        includeMembership: [ 'group' ],
        filter: group.query
      };
      ad.findGroups(opts, function(err, groups) {
        if (err) return(done(err));
        assert(groups);

        // Not verifying actual group results, just verifying that groups attribute
        // exists. Not all groups may have groups.
        assert(_.any(groups || [], function(group) {
          return(group.groups);
        }));
        done();
      });
    });
    it('should not include groups/membership if opts.includeMembership disabled', function(done) {
      var group = settings.groups[0];
      var opts = {
        includeMembership: false,
        filter: group.query
      };
      ad.findGroups(opts, function(err, groups) {
        if (err) return(done(err));
        assert(groups);

        // Not verifying actual group results, just verifying that groups attribute
        // exists.
        assert(_.all(groups || [], function(group) {
          return(! group.groups);
        }));
        done();
      });
    });
    it('should return only requested attributes', function(done) {
      var group = settings.groups[0];
      var opts = {
        attributes: [ 'cn' ],
        filter: group.query
      };
      ad.findGroups(opts, function(err, groups) {
        if (err) return(done(err));
        assert(groups);

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

