module.exports = {
  url: 'ldap://127.0.0.1:1389',
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
