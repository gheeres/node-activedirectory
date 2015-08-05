var assert = require('./assert.more');
var _ = require('underscore');
var ActiveDirectory = require('../index');
var config = require('./config');

describe('ActiveDirectory', function() {
  var ad;
  var settings = require('./settings').findGroup;

  before(function() {
   ad = new ActiveDirectory(config);
  });

  describe('#findGroup()', function() {
    [ 'cn', 'dn' ].forEach(function(groupAttribute) {
      it('should return user for (' + groupAttribute + ') ' + settings.groupName[groupAttribute], function(done) {
        ad.findGroup(settings.groupName[groupAttribute], function(err, user) {
          if (err) return(done(err));
          assert(user);
          done();
        });
      });
    });
    it('should return undefined if the group doesn\'t exist', function(done) {
      ad.findGroup('!!!NON-EXISTENT GROUP!!!', function(err, user) {
        if (err) return(done(err));
        assert(! user);
        done();
      });
    });
    it('should return default group attributes when not specified', function(done) {
      var defaultAttributes = [ 'dn', 'objectCategory', 'cn', 'description' ];
      ad.findGroup(settings.groupName.dn, function(err, user) {
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

  describe('#findGroup(opts)', function() {
    it('should use the custom opts.filter if provided', function(done) {
      var opts = {
        filter: settings.opts.custom
      };
      ad.findGroup(opts, settings.groupName.dn, function(err, user) {
        if (err) return(done(err));
        assert(user);

        assert((settings.groupName.dn || '').toLowerCase() !== (user.dn || '').toLowerCase());
        done();
      });
    });
    it('should include groups/membership if opts.includeMembership[] = [ \'all\' ]', function(done) {
      var opts = {
        includeMembership: [ 'all' ]
      };
      ad.findGroup(opts, settings.groupName.dn, function(err, user) {
        if (err) return(done(err));
        assert(user);

        assert.equalDifference(settings.groups || [], user.groups || []);
        done();
      });
    });
    it('should include groups/membership if opts.includeMembership[] = [ \'group\' ]', function(done) {
      var opts = {
        includeMembership: [ 'group' ]
      };
      ad.findGroup(opts, settings.groupName.dn, function(err, user) {
        if (err) return(done(err));
        assert(user);

        assert.equalDifference(settings.groups || [], user.groups || []);
        done();
      });
    });
    it('should return expected groups/membership if opts.includeMembership enabled', function(done) {
      var opts = {
        includeMembership: [ 'group', 'all' ]
      };
      ad.findGroup(opts, settings.groupName.dn, function(err, user) {
        if (err) return(done(err));
        assert(user);

        assert.equalDifference(settings.groups || [], user.groups || []);
        done();
      });
    });
    it('should return only the first group if more than one result returned', function(done) {
      var opts = {
        filter: settings.opts.multipleFilter
      };
      ad.findGroup(opts, '' /* ignored since we're setting our own filter */, function(err, user) {
        if (err) return(done(err));
        assert(user);

        assert(! _.isArray(user));
        done();
      });
    });
    it('should return only requested attributes', function(done) {
      var opts = {
        attributes: [ 'createdTimestamp' ]
      };
      ad.findGroup(opts, settings.groupName.dn, function(err, user) {
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

