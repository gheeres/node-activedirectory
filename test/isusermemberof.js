var assert = require('assert');
var ActiveDirectory = require('../index');
var config = require('./config');

describe('ActiveDirectory', function() {
  var ad;
  var settings = require('./settings').isUserMemberOf;

  before(function() {
   ad = new ActiveDirectory(config);
  });

  describe('#isusermemberof()', function() {
    it('should return true if the username (sAMAccountName) is a member of the groupName (commonName)', function(done) {
      ad.isUserMemberOf(settings.sAMAccountName, settings.groupName.cn, function(err, isMember) {
        if (err) return(done(err));
        assert(isMember);
        done();
      });
    });
    it('should return true if the username (sAMAccountName) is a member of the groupName (distinguishedName)', function(done) {
      ad.isUserMemberOf(settings.sAMAccountName, settings.groupName.dn, function(err, isMember) {
        if (err) return(done(err));
        assert(isMember);
        done();
      });
    });
    it('should return true if the username (userPrincipalName) is a member of the groupName (commonName)', function(done) {
      ad.isUserMemberOf(settings.userPrincipalName, settings.groupName.cn, function(err, isMember) {
        if (err) return(done(err));
        assert(isMember);
        done();
      });
    });
    it('should return true if the username (userPrincipalName) is a member of the groupName (distinguishedName)', function(done) {
      ad.isUserMemberOf(settings.userPrincipalName, settings.groupName.dn, function(err, isMember) {
        if (err) return(done(err));
        assert(isMember);
        done();
      });
    });
    it('should return true if the username (distinguishedName) is a member of the groupName (commonName)', function(done) {
      ad.isUserMemberOf(settings.dn, settings.groupName.cn, function(err, isMember) {
        if (err) return(done(err));
        assert(isMember);
        done();
      });
    });
    it('should return true if the username (distinguishedName) is a member of the groupName (distinguishedName)', function(done) {
      ad.isUserMemberOf(settings.dn, settings.groupName.dn, function(err, isMember) {
        if (err) return(done(err));
        assert(isMember);
        done();
      });
    });
    it('should return false if the username (sAMAccountName) is not a member of the groupName', function(done) {
      ad.isUserMemberOf(settings.sAMAccountName, '!!!NON-EXISTENT GROUP!!!', function(err, isMember) {
        if (err) return(done(err));
        assert(! isMember);
        done();
      });
    });
    it('should return false if the username (userPrincipalName) is not a member of the groupName', function(done) {
      ad.isUserMemberOf(settings.userPrincipalName, '!!!NON-EXISTENT GROUP!!!', function(err, isMember) {
        if (err) return(done(err));
        assert(! isMember);
        done();
      });
    });
    it('should return false if the username (distinguishedName) is not a member of the groupName', function(done) {
      ad.isUserMemberOf(settings.dn, '!!!NON-EXISTENT GROUP!!!', function(err, isMember) {
        if (err) return(done(err));
        assert(! isMember);
        done();
      });
    });
    it('should return true if the username is a member of a nested groupName', function(done) {
      ad.isUserMemberOf(settings.sAMAccountName, settings.groupName.nested, function(err, isMember) {
        if (err) return(done(err));
        assert(isMember);
        done();
      });
    });
  });
});

