var assert = require('assert');
var _ = require('underscore');
var ActiveDirectory = require('../index');
var config = require('./config');

describe('ActiveDirectory', function() {
  var ad;
  var settings = require('./settings').findUser;

  var defaultAttributes = [
    'dn',
    'userPrincipalName', 'sAMAccountName', 'mail',
    'lockoutTime', 'whenCreated', 'pwdLastSet', 'userAccountControl',
    'employeeID', 'sn', 'givenName', 'initials', 'cn', 'displayName',
    'comment', 'description' 
  ];

  before(function() {
  });

  it('should return default user attributes when not specified', function(done) {
    ad = new ActiveDirectory(config);
    ad.findUser(settings.username.userPrincipalName, function(err, user) {
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

  it('when default attributes contains a wildcard, should return all attributes', function(done) {
    var localConfig = _.extend({}, config, {
      attributes: {
        user: [ '*' ]
      }
    });
    ad = new ActiveDirectory(localConfig);
    ad.findUser(settings.username.userPrincipalName, function(err, user) {
      if (err) return(done(err));
      assert(user);

      var attributes = _.keys(user) || [];
      assert(attributes.length > defaultAttributes.length);
      done();
    });
  });
  it('when default attributes is empty array, should return all attributes', function(done) {
    var localConfig = _.extend({}, config, {
      attributes: {
        user: [ ]
      }
    });
    ad = new ActiveDirectory(localConfig);
    ad.findUser(settings.username.userPrincipalName, function(err, user) {
      if (err) return(done(err));
      assert(user);

      var attributes = _.keys(user) || [];
      assert(attributes.length > defaultAttributes.length);
      done();
    });
  });

  it('when opts.attributes contains a wildcard, should return all attributes', function(done) {
    var opts = {
      attributes: [ '*' ]
    };
    ad = new ActiveDirectory(config);
    ad.findUser(opts, settings.username.userPrincipalName, function(err, user) {
      if (err) return(done(err));
      assert(user);

      var attributes = _.keys(user) || [];
      assert(attributes.length > defaultAttributes.length);
      done();
    });
  });
  it('when opts.attributes is empty array, should return all attributes', function(done) {
    var opts = {
      attributes: [ ]
    };
    ad = new ActiveDirectory(config);
    ad.findUser(opts, settings.username.userPrincipalName, function(err, user) {
      if (err) return(done(err));
      assert(user);

      var attributes = _.keys(user) || [];
      assert(attributes.length > defaultAttributes.length);
      done();
    });
  });
});

