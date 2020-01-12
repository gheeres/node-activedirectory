'use strict'

/**
 * <p>This is a subclass implementation of ldapjs.Server. It's purpose is to
 * allow Active Directory style credential authorizations, e.g.:</p>
 *
 * <ul>
 *   <li>username</li>
 *   <li>username@domain</li>
 *   <li>domain\username</li>
 * </ul>
 *
 * <p>Where possible, we use the super class methods unaltered.</p>
 *
 * @type {EventEmitter}
 */

const EventEmitter = require('events').EventEmitter
const net = require('net')
const tls = require('tls')
const util = require('util')
const FakeDN = require('./FakeDN')
const settings = require('../settings')
const ldap = require('ldapjs')
const Protocol = require('ldapjs/lib/protocol')
const errors = require('ldapjs/lib/errors')
const connectionHandler = require('./connectionHandler')
const authenticationFactory = require('./authentication')
const searchFactory = require('./search')

const pino = require('pino')
let log = pino({ level: 'info' })

// We have to re-implement the whole constructor because we can't modify
// its internal connection listener. And we need to do that so that we can
// create invalid DNs to match what Active Directory allows.
//
// Most of this method is copied and pasted from the ldapjs.Server code.
// For legibility, large portions of it are moved to connectionHandler.js,
// setupConnection.js, and getResponse.js.
function Server (options) {
  if (options) {
    if (typeof (options) !== 'object') {
      throw new TypeError('options (object) required')
    }

    if (typeof (options.log) !== 'object') {
      throw new TypeError('options.log must be an object')
    }

    if (options.certificate || options.key) {
      if (!(options.certificate && options.key) ||
          (typeof (options.certificate) !== 'string' &&
          !Buffer.isBuffer(options.certificate)) ||
          (typeof (options.key) !== 'string' &&
          !Buffer.isBuffer(options.key))) {
        throw new TypeError('options.certificate and options.key ' +
                            '(string or buffer) are both required for TLS')
      }
    }
  } else {
    options = {}
  }
  const self = this

  EventEmitter.call(this, options)

  this._chain = []
  this.log = log = options.log
  this.strictDN = (options.strictDN !== undefined) ? options.strictDN : true

  this.routes = {}
  if ((options.cert || options.certificate) && options.key) {
    options.cert = options.cert || options.certificate
    this.server = tls.createServer(options, connectionHandler(this, log, options))
  } else {
    this.server = net.createServer(connectionHandler(this, log, options))
  }
  this.server.log = options.log
  this.server.ldap = {
    config: options
  }
  this.server.on('close', function () {
    self.emit('close')
  })
  this.server.on('error', function (err) {
    self.emit('error', err)
  })

  Object.defineProperties(this, {
    connections: {
      get: function () {
        return this.server.connections
      }
    },
    maxConnections: {
      get: function () {
        return this.server.maxConnections
      },
      set: function (val) {
        this.server.maxConnections = val
      }
    },
    name: {
      value: 'MockLDAPServer'
    },
    url: {
      get: function () {
        let str
        if (!this.server.address().family) {
          str = 'ldapi://'
          str += this.host.replace(new RegExp('/', 'g'), '%2f')
          return str
        }
        if (this.server instanceof tls.Server) {
          str = 'ldaps://'
        } else {
          str = 'ldap://'
        }
        str += self.host || 'localhost'
        str += ':'
        str += self.port || 389
        return str
      }
    }
  })
}
util.inherits(Server, ldap.Server)

// We have to override the bind method so that we can handle weird usernames
Server.prototype.bind = function bind (name) {
  const args = Array.prototype.slice.call(arguments, 1)
  if (name.indexOf('@') !== -1 || name.indexOf('\\') !== -1) {
    return this._mount(0x60, name, args, true)
  }

  ldap.Server.prototype.bind.apply(this, arguments)
}

Server.prototype._getHandlerChain = function _getHandlerChain (req, res) {
  if (req.protocolOp === Protocol.LDAP_REQ_BIND &&
      req.dn.toString() === 'AnInvalidUsername') {
    return {
      backend: this,
      handlers: [function (req, res, next) {
        res.status = errors.LDAP_INVALID_CREDENTIALS
        res.matchedDN = req.suffix ? req.suffix.toString() : ''
        res.errorMessage = ''
        res.end(res.status)
        return next()
      }]
    }
  }
  return ldap.Server.prototype._getHandlerChain.apply(this, arguments)
}

// We have to override _sortedRouteKeys so that weird username routes don't
// get culled
Server.prototype._sortedRouteKeys = function _sortedRouteKeys () {
  return Object.keys(this.routes)
}

// Scoped function that ldapjs.Server depends upon. This is a strait copy
// and paste.
function mergeFunctionArgs (argv, start, end) {
  if (!start) {
    start = 0
  }

  if (!end) {
    end = argv.length
  }

  const handlers = []

  for (let i = start; i < end; i++) {
    if (argv[i] instanceof Array) {
      const arr = argv[i]
      for (let j = 0; j < arr.length; j++) {
        if (!(arr[j] instanceof Function)) {
          throw new TypeError('Invalid argument type: ' + typeof (arr[j]))
        }
        handlers.push(arr[j])
      }
    } else if (argv[i] instanceof Function) {
      handlers.push(argv[i])
    } else {
      throw new TypeError('Invalid argument type: ' + typeof (argv[i]))
    }
  }

  return handlers
}

// We have to override _mount so that DN parsing will work with weird usernames.
// We have simplified the upstream function to always return a FakeDN instance
// instead of either a plain string or a DN instance.
Server.prototype._mount = function (op, name, argv) {
  if (typeof (name) !== 'string') {
    throw new TypeError('name (string) required')
  }

  if (!argv.length) {
    throw new Error('at least one handler required')
  }

  let backend = this
  let index = 0

  if (typeof (argv[0]) === 'object' && !Array.isArray(argv[0])) {
    backend = argv[0]
    index = 1
  }
  const route = this._getRoute(FakeDN.parse(name), backend)

  const chain = this._chain.slice()
  argv.slice(index).forEach(function (a) {
    chain.push(a)
  })
  route['0x' + op.toString(16)] = mergeFunctionArgs(chain)

  return this
}

module.exports = function (cb) {
  const server = new Server({
    strictDN: false,
    log: log
  })

  authenticationFactory(server, settings)
  searchFactory(server, settings)

  server.listen(0, '127.0.0.1', function (err) {
    cb(err, server)
  })
}
