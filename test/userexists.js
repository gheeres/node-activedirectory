var assert = require('assert');
var ActiveDirectory = require('../index');
var config = require('./config');

describe('ActiveDirectory', function() {
  describe('#userExists()', function() {
    var ad;
    var settings = require('./settings').userExists;

    beforeEach(function() {
     ad = new ActiveDirectory(config);
    });

    it('should return true if the username (sAMAccountName) exists', function(done) {
      ad.userExists(settings.username.sAMAccountName, function(err, exists) {
        if (err) return(done(err));
        assert(exists);
        done();
      });
    });
    it('should return true if the username (userPrincipalName) exists', function(done) {
      ad.userExists(settings.username.userPrincipalName, function(err, exists) {
        if (err) return(done(err));
        assert(exists);
        done();
      });
    });
    it('should return true if the username (distinguishedName) exists', function(done) {
      ad.userExists(settings.username.sAMAccountName, function(err, exists) {
        if (err) return(done(err));
        assert(exists);
        done();
      });
    });
    it('should return false if the username doesn\'t exist', function(done) {
      ad.userExists('!!!NON-EXISTENT USER!!!', function(err, exists) {
        if (err) return(done(err));
        assert(! exists);
        done();
      });
    });
  });
});

