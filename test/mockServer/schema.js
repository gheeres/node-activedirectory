'use strict';

const RDN = require('ldapjs/lib/dn').RDN;

const groupCategory = 'CN=Group,CN=Schema,CN=Configuration,DC=domain,DC=com';
const personCategory = 'CN=Person,CN=Schema,CN=Configuration,DC=domain,DC=com';
const schema = {};

schema.com = {
  type: 'dc'
};
schema.com.domain = {
  type: 'dc'
};

// Groups
schema.com.domain['domain groups'] = {
  type: 'ou'
};
[
  'Authors', 'Domain Admins', 'My Users', 'VPN Users', 'Web Administrator'
].forEach((n) => {
  schema.com.domain['domain groups'][n.toLowerCase()] = {
    type: 'cn',
    value: {
      dn: `CN=${n},OU=Domain Groups,DC=domain,DC=com`,
      attributes: {
        cn: `${n}`,
        distinguishedName: `CN=${n},OU=Domain Groups,DC=domain,DC=com`,
        description: `${n} group`,
        groupType: 1,
        objectClass: ['group'],
        objectCategory: groupCategory
      }
    }
  }
});

// Users
function createUserObject(firstName, lastName, initials, username, ou, groups) {
  const user = {
    dn: `CN=${firstName} ${lastName},OU=${ou},DC=domain,DC=com`,
    attributes: {
      userPrincipalName: `${username}@domain.com`,
      sAMAccountName: username,
      domainUsername: `DOMAIN\\${username}`,
      mail: `${username}@domain.com`,
      lockoutTime: 0,
      whenCreated: 0,
      pwdLastSet: 0,
      userAccountControl: 0,
      employeeID: 0,
      sn: lastName,
      givenName: firstName,
      initials: initials,
      cn: `CN=${firstName} ${lastName},OU=Domain Users,DC=domain,DC=com`,
      displayName: `${firstName} ${lastName}`,
      comment: 'none',
      description: 'none',
      objectCategory: personCategory,
      extraAttributeForTesting: '',
      memberOf: []
    }
  };

  groups.forEach((g) => {
    user.attributes.memberOf.push(
      schema.com.domain['domain groups'][g.toLowerCase()].value
    );
  });

  return user;
}

schema.com.domain['domain users'] = {
  type: 'ou',
  'first last name': {
    type: 'cn',
    value: createUserObject(
      'First',
      'Last Name',
      'FLN',
      'username',
      'Domain Users',
      ['my users', 'vpn users', 'authors']
    )
  }
};

schema.com.domain['domain admins'] = {
  type: 'ou',

  'web administrator': {
    type: 'cn',
    value: createUserObject(
      'Web',
      'Administrator',
      'WA',
      'webadmin',
      'Domain Admins',
      ['my users', 'web administrator', 'domain admins']
    )
  }
};

// methods
schema.getByRDN = function getByRDN(rdn) {
  let _rdn;
  if (rdn instanceof RDN) {
    _rdn = rdn.toString().toLowerCase();
  } else if (!(typeof rdn === 'string')) {
    throw new Error('rdn must be a string or instance of RDN');
  } else {
    _rdn = rdn.toLowerCase();
  }

  const components = _rdn.split(',');
  const path = [];
  for (let i = (components.length - 1); i >= 0; i = i - 1) {
    path.push(components[i].split('=')[1].replace(/[()]/g, ''));
  }

  let result = schema;
  for (let p of path) {
    result = result[p];
  }

  return result.value;
};

module.exports = schema;