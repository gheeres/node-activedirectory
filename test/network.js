var assert = require('assert');
var ActiveDirectory = require('../index');

describe('ActiveDirectory', function() {
  var username = 'username';
  var password = 'password';

  describe('#authenticate()', function() {
    it('should return err (ENOTFOUND) on invalid hostname (dns)', function(done) {
      var ad = new ActiveDirectory({
        url: 'ldap://invalid.domain.net'
      });
      ad.authenticate(username, password, function(err, auth) {
        assert((err || {}).code === 'ENOTFOUND');
        assert(! auth);
        done();
      });
    });
    it('should return err (ECONNREFUSED) on non listening port', function(done) {
      var ad = new ActiveDirectory({
        url: 'ldap://127.0.0.1/'
      });
      ad.authenticate(username, password, function(err, auth) {
        assert((err || {}).code === 'ECONNREFUSED');
        assert(! auth);
        done();
      });
    });
  });
});

