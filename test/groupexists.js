var assert = require('assert');
var ActiveDirectory = require('../index');
var config = require('./config');

describe('ActiveDirectory', function() {
  var ad;
  var settings = require('./settings').groupExists;

  before(function() {
   ad = new ActiveDirectory(config);
  });

  describe('#groupExists()', function() {
    it('should return true if the groupName (commonName) exists', function(done) {
      ad.groupExists(settings.sAMAccountName, settings.groupName.cn, function(err, exists) {
        if (err) return(done(err));
        assert(exists);
        done();
      });
    });
    it('should return true if the groupName (distinguishedName) exists', function(done) {
      ad.groupExists(settings.sAMAccountName, settings.groupName.dn, function(err, exists) {
        if (err) return(done(err));
        assert(exists);
        done();
      });
    });
    it('should return false if the groupName doesn\'t exist', function(done) {
      ad.groupExists(settings.sAMAccountName, '!!!NON-EXISTENT GROUP!!!', function(err, exists) {
        if (err) return(done(err));
        assert(! exists);
        done();
      });
    });
  });
});

