const winston = require('winston');
module.exports = {
  url: 'ldap://127.0.0.1:1389',
  baseDN: 'dc=domain,dc=com',
  username: 'auth@domain.com',
  //username: 'CN=Authenticator,OU=Special Uesrs,DC=domain,DC=com',
  password: 'password',
  logging: new winston.Logger({
    transports: [
      new winston.transports.Console({
        colorize: true,
        level: 'error'
      })
    ]
  })
};
