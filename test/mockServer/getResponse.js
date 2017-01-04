'use strict'

const Protocol = require('ldapjs/lib/protocol')
const AbandonResponse = require('ldapjs/lib/messages/abandon_response')
const AddResponse = require('ldapjs/lib/messages/add_response')
const BindResponse = require('ldapjs/lib/messages/bind_response')
const CompareResponse = require('ldapjs/lib/messages/compare_response')
const DeleteResponse = require('ldapjs/lib/messages/del_response')
const ExtendedResponse = require('ldapjs/lib/messages/ext_response')
const ModifyResponse = require('ldapjs/lib/messages/modify_response')
const ModifyDNResponse = require('ldapjs/lib/messages/moddn_response')
const SearchRequest = require('ldapjs/lib/messages/search_request')
const SearchResponse = require('ldapjs/lib/messages/search_response')
const UnbindResponse = require('ldapjs/lib/messages/unbind_response')

// This is a copy and paste of the ldapjs implementation.

module.exports = function getResponse (req) {
  let Response

  switch (req.protocolOp) {
    case Protocol.LDAP_REQ_BIND:
      Response = BindResponse
      break
    case Protocol.LDAP_REQ_ABANDON:
      Response = AbandonResponse
      break
    case Protocol.LDAP_REQ_ADD:
      Response = AddResponse
      break
    case Protocol.LDAP_REQ_COMPARE:
      Response = CompareResponse
      break
    case Protocol.LDAP_REQ_DELETE:
      Response = DeleteResponse
      break
    case Protocol.LDAP_REQ_EXTENSION:
      Response = ExtendedResponse
      break
    case Protocol.LDAP_REQ_MODIFY:
      Response = ModifyResponse
      break
    case Protocol.LDAP_REQ_MODRDN:
      Response = ModifyDNResponse
      break
    case Protocol.LDAP_REQ_SEARCH:
      Response = SearchResponse
      break
    case Protocol.LDAP_REQ_UNBIND:
      Response = UnbindResponse
      break
    default:
      return null
  }

  var res = new Response({
    messageID: req.messageID,
    log: req.log,
    attributes: ((req instanceof SearchRequest) ? req.attributes : undefined)
  })
  res.connection = req.connection
  res.logId = req.logId

  return res
}
