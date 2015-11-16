var assert = require('assert');
var _ = require('underscore');
var ActiveDirectory = require('../index');
var config = require('./config');

describe('ActiveDirectory', function() {
  var settings = require('./settings').ctor;

  describe('#ctor()', function() {
    it('should support legacy parameters (url, baseDN, username, password)', function(done) {
      var ad = new ActiveDirectory(config.url, config.baseDN, config.username, config.password);
      assert.equal(config.baseDN, ad.baseDN);
      assert.equal(config.url, ad.opts.url);
      assert.equal(config.username, ad.opts.bindDN);
      assert.equal(config.password, ad.opts.bindCredentials);
      done();
    });
    it('should set parameters from configuration object', function(done) {
      var ad = new ActiveDirectory(config);
      assert.equal(config.baseDN, ad.baseDN);
      assert.equal(config.url, ad.opts.url);
      assert.equal(config.username, ad.opts.bindDN);
      assert.equal(config.password, ad.opts.bindCredentials);
      done();
    });
    it('should set opts.maxConnections = 20', function(done) {
      var ad = new ActiveDirectory(config);
      assert.equal(20, ad.opts.maxConnections);
      done();
    });
    it('should replace default user attributes if specified', function(done) {
      var ad = new ActiveDirectory(_.extend({}, config, {
        attributes: {
          user: [ 'mycustomuserattribute' ]
        }
      }));
      var defaultAttributes = ad._getDefaultAttributes() || {};
      assert.equal(1, (defaultAttributes.user || []).length);
      assert((defaultAttributes.group || []).length > 0);
      done();
    });
    it('should replace default group attributes if specified', function(done) {
      var ad = new ActiveDirectory(_.extend({}, config, {
        attributes: {
          group: [ 'mycustomgroupattribute' ]
        }
      }));
      var defaultAttributes = ad._getDefaultAttributes() || {};
      assert.equal(1, (defaultAttributes.group || []).length);
      assert((defaultAttributes.user || []).length > 0);
      done();
    });
    it('should throw an InvalidCredentialsError exception if the username/password are incorrect.', function(done) {
      var ad = new ActiveDirectory(_.extend({}, config, {
        password: 'TheWrongPassword!',
        username: 'AnInvalidUsername',
      }));
      ad.findUser('unknown', function(err, user) {
        assert.notEqual(null, err);
        assert.equal(err.name, 'InvalidCredentialsError');
        done();
      });
    });
  });
});

