var assert = require('assert');
var ActiveDirectory = require('../index');
var config = require('./config');

describe('ActiveDirectory', function() {
  var ad;
  var settings = require('./settings').authenticate;

  before(function() {
   ad = new ActiveDirectory(config);
  });

  describe('#authenticate()', function() {
    it('should return true if the username (distinguishedName) and password are correct', function(done) {
      ad.authenticate(settings.username.dn, settings.password, function(err, auth) {
        if (err) return(done(err));
        assert(auth);
        done();
      });
    });
    it('should return true if the username (userPrincipalName) and password are correct', function(done) {
      ad.authenticate(settings.username.userPrincipalName, settings.password, function(err, auth) {
        if (err) return(done(err));
        assert(auth);
        done();
      });
    });
    it('should return true if the username (DOMAIN\\username) and password are correct', function(done) {
      ad.authenticate(settings.username.domainUsername, settings.password, function(err, auth) {
        if (err) return(done(err));
        assert(auth);
        done();
      });
    });
    it('should return empty or null err if the username and password are correct', function(done) {
      ad.authenticate(settings.username.domainUsername, settings.password, function(err, auth) {
        assert(! err);
        done();
      });
    });
    it('should return false if username is null', function(done) {
      ad.authenticate(null, settings.password, function(err, auth) {
        assert(! auth);
        done();
      });
    });
    it('should return false if username is an empty string.', function(done) {
      ad.authenticate('', settings.password, function(err, auth) {
        assert(! auth);
        done();
      });
    });
    it('should return false if username and password are incorrect', function(done) {
      ad.authenticate('!!!INVALID USERNAME!!!', '!!!INVALID PASSWORD!!!', function(err, auth) {
        assert(! auth);
        done();
      });
    });
    it('should return err with LDAP_INVALID_CREDENTIALS if username and password are incorrect', function(done) {
      ad.authenticate('!!!INVALID USERNAME!!!', '!!!INVALID PASSWORD!!!', function(err, auth) {
        var LDAP_INVALID_CREDENTIALS = 49;
        assert((err || {}).code === LDAP_INVALID_CREDENTIALS);
        done();
      });
    });
  });
});

