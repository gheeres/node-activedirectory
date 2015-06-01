module.exports = {
  url: 'ldap://domain.com',
  baseDN: 'dc=domain,dc=com',
  username: 'auth@domain.com',
  //username: 'CN=Authenticator,OU=Special Uesrs,DC=domain,DC=com',
  password: 'password',
  logging: {
    name: 'ActiveDirectory',
    streams: [
      { level: 'error',
        stream: process.stdout }
    ]
  }
};
