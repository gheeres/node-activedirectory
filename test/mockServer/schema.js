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
  'Account - Department #1', 'Account - Department #2',
  'Account - Department #3', 'Account - Department #4',
  'All Directors', 'Another Group', 'Authors', 'Budget Users', 'Domain Admins',
  'My Group', 'My Group #1', 'My Group #2', 'My Nested Users', 'My Users',
  'Parking Department', 'Parking Users', 'Security Users', 'Security Owners',
  'System Directors',
  'VPN Users',
  'Web Administrator', 'Yet Another Group'
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

schema.com.domain['domain groups']['my nested users']
  .value.attributes.memberOf = [
    schema.com.domain['domain groups']['my users'].value
  ];

schema.com.domain['distribution lists'] = {
  type: 'ou',

  'all users': {
    type: 'cn',
    value: {
      dn: 'CN=All Users,OU=Distribution Lists,DC=domain,DC=com',
      attributes: {
        cn: 'All Users',
        distinguishedName: 'CN=All Users,OU=Distribution Lists,DC=domain,DC=com',
        description: 'All Users distribution list',
        groupType: 1,
        objectClass: ['group'],
        objectCategory: groupCategory
      }
    }
  }
};

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
      distinguishedName: `CN=${firstName} ${lastName},OU=Domain Users,DC=domain,DC=com`,
      displayName: `${firstName} ${lastName}`,
      comment: 'none',
      description: 'none',
      objectCategory: personCategory,
      extraAttributeForTesting: '',
      memberOf: []
    }
  };

  groups.forEach((g) => {
    const gLower = g.toLowerCase();
    if (Object.keys(schema.com.domain['domain groups']).indexOf(gLower) !== -1) {
      user.attributes.memberOf.push(
        schema.com.domain['domain groups'][gLower].value
      );
    }
    if (Object.keys(schema.com.domain['distribution lists']).indexOf(gLower) !== -1) {
      user.attributes.memberOf.push(
        schema.com.domain['distribution lists'][gLower].value
      );
    }
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
  },

  'first last name #1': {
    type: 'cn',
    value: createUserObject(
      'First',
      'Last Name #1',
      'FLN1',
      'username1',
      'Domain Users',
      ['all users', 'budget users']
    )
  },

  'first last name #2': {
    type: 'cn',
    value: createUserObject(
      'First',
      'Last Name #2',
      'FLN1',
      'username2',
      'Domain Users',
      ['all users']
    )
  },

  'first last name #3': {
    type: 'cn',
    value: createUserObject(
      'First',
      'Last Name #3',
      'FLN1',
      'username3',
      'Domain Users',
      ['all users']
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

schema.getGroup = function getGroup(cn) {
  const cnLower = cn.toLowerCase();
  let group;

  if (Object.keys(schema.com.domain['domain groups']).indexOf(cnLower) !== -1) {
    group = schema.com.domain['domain groups'][cnLower];
  } else {
    group = schema.com.domain['distribution lists'][cnLower];
  }

  group.value.attributes.member = schema.getGroupMembers(
    group.value.attributes.cn
  );
  return group.value;
};

schema.getGroupMembers = function getGroupMembers(groupCN) {
  const domainUsers = schema.com.domain['domain users'];
  const adminUsers = schema.com.domain['domain admins'];
  const members = [];

  function loopUsers(users) {
    for (let k of Object.keys(users)) {
      if (!users[k].hasOwnProperty('type')) {
        continue;
      }
      if (!users[k].value.attributes.memberOf) {
        continue;
      }
      for (let g of users[k].value.attributes.memberOf) {
        if (g.attributes.cn.toLowerCase() === groupCN.toLowerCase()) {
          members.push(users[k].value.attributes.cn);
        }
      }
    }
  }

  loopUsers(domainUsers);
  loopUsers(adminUsers);

  return members;
};

module.exports = schema;