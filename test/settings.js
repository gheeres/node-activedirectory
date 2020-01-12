module.exports = {
  // Test settings for authentication
  authenticate: {
    username: {
      userPrincipalName: 'username@domain.com',
      domainUsername: 'DOMAIN\\username',
      dn: 'CN=First Last Name,OU=Domain Users,DC=domain,DC=com'
    },
    password: 'password'
  },
  // Test settings for isUserMemberOf
  isUserMemberOf: {
    sAMAccountName: 'username',
    userPrincipalName: 'username@domain.com',
    dn: 'CN=First Last Name,OU=Domain Users,DC=domain,DC=com',
    groupName: {
      dn: 'CN=My Users,OU=Domain Groups,DC=domain,DC=com',
      cn: 'My Users',
      // CN or DN of an indirect or nested group membership.
      // (i.e. member of a group that contains a group that the user is a member of)
      nested: 'My Nested Users'
    }
  },
  // Test settings for groupExists
  groupExists: {
    groupName: {
      dn: 'CN=My Users,OU=Domain Groups,DC=domain,DC=com',
      cn: 'My Users'
    }
  },
  // Test settings for userExists
  userExists: {
    username: {
      userPrincipalName: 'username@domain.com',
      sAMAccountName: 'username',
      dn: 'CN=First Last Name,OU=Domain Users,DC=domain,DC=com'
    }
  },
  // Test settings for getGroupMembershipForGroup
  getGroupMembershipForGroup: {
    groups: [{
      dn: 'CN=My Users,OU=Domain Groups,DC=domain,DC=com',
      cn: 'My Users',
      // The list of groups (commonName) that this group is a member of.
      members: [
        'VPN Users', 'Web Users'
      ]
    }, {
      dn: 'CN=Authors,OU=Domain Groups,DC=domain,DC=com',
      cn: 'Authors',
      // The list of groups (commonName) that this group is a member of.
      members: [
        'Editors', 'Contributors', 'Web Editors', 'Web Users'
      ]
    }]
  },
  // Test settings for getGroupMembershipForUser
  getGroupMembershipForUser: {
    users: [{
      dn: 'CN=First Last Name,OU=Domain Users,DC=domain,DC=com',
      sAMAccountName: 'username',
      userPrincipalName: 'username@domain.com',
      // The list of groups (commonName) that this user is a member of.
      members: [
        'My Users', 'VPN Users', 'Authors'
      ]
    }, {
      dn: 'CN=Celebrity Circular,OU=Domain Users,DC=domain,DC=com',
      sAMAccountName: 'celeb',
      userPrincipalName: 'celeb@domain.com',
      // The list of groups (commonName) that this user is a member of.
      members: [
        'grpa', 'grpb'
      ]
    }, {
      dn: 'CN=Web Administrator,OU=Domain Admins,DC=domain,DC=com',
      sAMAccountName: 'webadmin',
      userPrincipalName: 'webadmin@domain.com',
      // The list of groups (commonName) that this user is a member of.
      members: [
        'My Users', 'Web Administrator', 'Domain Admins'
      ]
    }]
  },
  // Test settings for getGroupMembershipForGroup
  getUsersForGroup: {
    groups: [{
      dn: 'CN=All Users,OU=Distribution Lists,DC=domain,DC=com',
      cn: 'All Users',
      // The list of users (dn) that are members of this group.
      users: [
        'CN=First Last Name #1,OU=Domain Users,DC=domain,DC=com',
        'CN=First Last Name #2,OU=Domain Users,DC=domain,DC=com',
        'CN=First Last Name #3,OU=Domain Users,DC=domain,DC=com'
      ]
    }, {
      dn: 'CN=Budget Users,OU=Domain Groups,DC=domain,DC=com',
      cn: 'Budget Users',
      // The list of users (dn) that are members of this group.
      users: [
        'CN=First Last Name #1,OU=Domain Users,DC=domain,DC=com'
      ]
    }]
  },
  // Test settings for findUser
  findUser: {
    username: {
      userPrincipalName: 'username@domain.com',
      sAMAccountName: 'username',
      dn: 'CN=First Last Name,OU=Domain Users,DC=domain,DC=com'
    },
    // The list of groups that this user is a member of
    groups: [
      'My Users', 'Authors'
    ],
    opts: {
      custom: '(userPrincipalName=anotheruser@domain.com)', // Make sure this user is different than the one specified
      // in username.userPrincipalName
      multipleFilter: '(CN=Smith*)' // Ensure this query returns more than one user.
    }
  },
  // Test settings for findGroup
  findGroup: {
    groupName: {
      dn: 'CN=My Group,OU=Domain Groups,DC=domain,DC=com',
      cn: 'My Group'
    },
    groups: [
      'Another Group', 'Yet Another Group', 'Authors'
    ],
    opts: {
      custom: '(cn=Budget Users)', // Make sure this user is different than the one specified
      // in groupname.cn
      multipleFilter: '(&(objectCategory=Group)(cn=Admin*))' // Ensure this query returns more than one user.
    }
  },
  findUsers: {
    users: [{
      query: 'CN=Smith*',
      results: [
        'John Smith', 'Bob Smith'
      ]
    }, {
      // A custom query that includes groups, should only return users results.
      query: 'CN=*Director',
      results: [
        'Budget Director', 'Accounts Receivable Director'
      ]
    }, {
      // A query that returns NO users.
      query: {
        filter: 'CN=My Group'
      },
      results: [
      ]
    }]
  },
  findGroups: {
    groups: [{
      query: 'CN=My Group*',
      results: [
        'My Group', 'My Group #1', 'My Group #2'
      ]
    }, {
      // A custom query that includes users, should only return group results.
      query: {
        filter: 'CN=*Director*'
      },
      results: [
        'All Directors', 'System Directors',
        'Budget Director', 'Accounts Receivable Director'
      ]
    }, {
      query: 'CN=Account - *',
      results: [
        'Account - Department #1', 'Account - Department #2',
        'Account - Department #3', 'Account - Department #4'
      ]
    }, {
      // A custom query that returns no groups
      query: 'userPrincipalName=pattendant1@domain.com',
      results: [
      ]
    }]
  },
  find: {
    queries: [{
      query: 'CN=Parking*',
      results: {
        users: [
          'Parking Attendant #1', 'Parking Attendant #2'
        ],
        groups: [
          'Parking Department', 'Parking Users'
        ],
        other: [
          'parking-computer-01', 'parking-computer-02'
        ]
      }
    }, {
      query: {
        filter: '(&(CN=Security*))'
      },
      results: {
        users: [
        ],
        groups: [
          'Security Users', 'Security Owners'
        ],
        other: [
          'security-test-01', 'security-test-02', 'security-audit-01'
        ]
      }
    }]
  }
}
