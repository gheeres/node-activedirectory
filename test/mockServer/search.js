'use strict';

const ldap = require('ldapjs');

const findUserFilter = '(&(objectcategory=User)(|(samaccountname=username@domain.com)(userprincipalname=username@domain.com)))';
const userExistsFilter = '(&(objectcategory=User)(|(samaccountname=username)(userprincipalname=username)))';
const groupExistsFilter1 = '(&(objectcategory=Group)(cn=My Users))';
const groupExistsFilter2 = '(&(objectcategory=Group)(distinguishedname=CN=My Users,OU=Domain Groups,DC=domain,DC=com))';

module.exports = function search(server, settings) {
  const findUser = settings.findUser;
  const groupExists = settings.groupExists;
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

  const myUsersGroup = {
    dn: groupExists.groupName.dn,
    attributes: {
      cn: groupExists.groupName.cn
    }
  };

  server.search(
    baseDN,
    function searchHandler(req, res, next) {
      switch (req.filter.toString()) {
        case findUserFilter:
        case userExistsFilter:
          return findUserSearch(req, res, next);
          break;

        case groupExistsFilter1:
        case groupExistsFilter2:
          res.send(myUsersGroup);
          res.end();
          break;

        default:
          res.end();
          break;
      }
    }
  );
};