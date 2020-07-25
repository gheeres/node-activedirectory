'use strict'

const util = require('util')
const Parser = require('ldapjs/lib/messages').Parser
const Protocol = require('ldapjs/lib/protocol')
const errors = require('ldapjs/lib/errors')
const dnParse = require('./FakeDN').parse
const getResponse = require('./getResponse')
const setupConnection = require('./setupConnection')

// The functions defined herein are all copied from the ldapjs implementation.
// The were all inlined in the Server constructor. For legibility, we have
// refactored them into their own file.
//
// This file merely defines the callbacks that will be used to handle incoming
// client connections and requests.

let log
let server
let options

function decodeDN (req, strict) {
  let parse
  if (strict) {
    parse = dnParse
  } else {
    parse = function (input) {
      try {
        return dnParse(input)
      } catch (e) {
        return input
      }
    }
  }
  switch (req.protocolOp) {
    case Protocol.LDAP_REQ_BIND:
      req.name = parse(req.name)
      break
    case Protocol.LDAP_REQ_ADD:
    case Protocol.LDAP_REQ_COMPARE:
    case Protocol.LDAP_REQ_DELETE:
      req.entry = parse(req.entry)
      break
    case Protocol.LDAP_REQ_MODIFY:
      req.object = parse(req.object)
      break
    case Protocol.LDAP_REQ_MODRDN:
      req.entry = parse(req.entry)
      // TODO: handle newRdn/Superior
      break
    case Protocol.LDAP_REQ_SEARCH:
      req.baseObject = parse(req.baseObject)
      break
    default:
      break
  }
}

function onData (data) {
  log.trace('data on %s: %s', this.ldap.id, util.inspect(data))
  this.parser.write(data)
}

function onError (err, message) {
  server.emit('error', new Error(`Parser error for ${this.ldap.id}`))

  if (!message) {
    return this.destroy()
  }

  const res = getResponse(message)
  if (!res) {
    return this.destroy()
  }

  res.status = 0x02 // protocol error
  res.errorMessage = err.toString()
  return this.end(res.toBer())
}

function onMessage (req) {
  req.connection = this
  req.logId = this.ldap.id + '::' + req.messageID
  req.startTime = new Date().getTime()

  if (log.debug()) {
    log.debug('%s: message received: req=%j', this.ldap.id, req.json)
  }

  const res = getResponse(req)
  if (!res) {
    log.warn('Unimplemented server method: %s', req.type)
    this.destroy()
    return false
  }

  // parse string DNs for routing/etc
  decodeDN(req, server.strictDN)

  res.connection = this
  res.logId = req.logId
  res.requestDN = req.dn

  const chain = server._getHandlerChain(req, res)

  let i = 0
  function messageResponse (err) {
    function sendError (err) {
      res.status = err.code || errors.LDAP_OPERATIONS_ERROR
      res.matchedDN = req.suffix ? req.suffix.toString() : ''
      res.errorMessage = err.message || ''
      return res.end(res.status)
    }

    function after () {
      if (!server._postChain || !server._postChain.length) {
        return
      }

      function next () {} // stub out next for the post chain

      server._postChain.forEach(function (c) {
        c.call(server, req, res, next)
      })
    }

    if (err) {
      log.trace('%s sending error: %s', req.logId, err.stack || err)
      server.emit('clientError', err)
      sendError(err)
      return after()
    }

    try {
      const next = messageResponse.bind(this)
      if (chain.handlers[i]) {
        return chain.handlers[i++].call(chain.backend, req, res, next)
      }

      if (req.protocolOp === Protocol.LDAP_REQ_BIND && res.status === 0) {
        this.ldap.bindDN = req.dn
      }

      return after()
    } catch (e) {
      if (!e.stack) {
        e.stack = e.toString()
      }
      log.error('%s uncaught exception: %s', req.logId, e.stack)
      return sendError(new errors.OperationsError(e.message))
    }
  }

  return messageResponse.call(this)
}

function connectionHandler (c) {
  setupConnection(server, log, options)(c)
  c.parser = new Parser({ log })

  c.on('data', onData.bind(c))
  c.parser.on('error', onError.bind(c))
  c.parser.on('message', onMessage.bind(c))
}

module.exports = function ($server, $log, $options) {
  server = $server
  log = $log
  options = $options
  return connectionHandler
}
