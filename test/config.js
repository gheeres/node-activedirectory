const pino = require('pino')

module.exports = function config (port = 1389) {
  return {
    url: `ldap://127.0.0.1:${port}`,
    baseDN: 'dc=domain,dc=com',
    username: 'auth@domain.com',
    // username: 'CN=Authenticator,OU=Special Uesrs,DC=domain,DC=com',
    password: 'password',
    reconnect: false,
    logging: pino({ level: 'silent' })
  }
}
