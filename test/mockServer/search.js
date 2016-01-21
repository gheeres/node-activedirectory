'use strict';

const ldap = require('ldapjs');

const findUserFilter = '(&(objectcategory=User)(|(samaccountname=username@domain.com)(userprincipalname=username@domain.com)))';

module.exports = function search(server, settings) {
  const findUser = settings.findUser;
  const baseDN = 'dc=domain,dc=com';

  function findUserSearch(req, res, next) {
    const object = {
      dn: findUser.username.dn,
      attributes: {
        userPrincipalName: findUser.username.userPrincipalName,
        sAMAccountName: findUser.username.sAMAccountName,
        mail: `${findUser.username.sAMAccountName}@domain.com`,
        lockoutTime: 0,
        whenCreated: 0,
        pwdLastSet: 0,
        userAccountControl: 0,
        employeeID: 0,
        sn: 'Last Name',
        givenName: 'First',
        initials: 'FLN',
        cn: findUser.username.dn,
        displayName: 'First Last Name',
        comment: 'none',
        description: 'none',
        extraAttributeForTesting: ''
      }
    };

    res.send(object);
    res.end();
  }

  server.search(
    baseDN,
    function searchHandler(req, res, next) {
      if (req.filter.toString() === findUserFilter) {
        return findUserSearch(req, res, next);
      }
    }
  );
};