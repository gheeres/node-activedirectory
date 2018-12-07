'use strict'

const util = require('util')
const events = require('events')
const RangeAttribute = require('./../client/RangeAttribute')

let log

module.exports = function init ($ad, $log) {
  log = $log
  return RangeAttributeParser
}

/**
 * Parses the distinguishedName (dn) to remove any invalid characters or to
 * properly escape the request.
 *
 * @private
 *   @param dn {String} The dn to parse.
 * @returns {String}
 */
function parseDistinguishedName (dn) {
  log.trace('parseDistinguishedName(%s)', dn)
  if (!dn) {
    return (dn)
  }

  dn = dn.replace(/"/g, '\\"')
  return dn.replace('\\,', '\\\\,')
}

/**
 * Represents a paged search result.
 *
 * @private
 * @param {object} result An LDAP search entry result.
 * @constructor
 */
function Result (result) {
  this.originalResult = result
  this.rangeAttributes = new Map()
  this.rangeAttributeResults = new Map()
}

Result.prototype.name = function name () {
  return this.originalResult.dn
}

/**
 * Populates the original search results's range valued attributes with the
 * retrieved values and returns the new search result.
 *
 * @returns {object}
 */
Result.prototype.value = function value () {
  const result = {}
  Object.getOwnPropertyNames(this.originalResult).forEach(
    k => { result[k] = this.originalResult[k] }
  )
  Array.from(this.rangeAttributes.keys()).forEach((k) => {
    result[k] = this.rangeAttributeResults.get(k)
  })
  return result
}

/**
 * Handles any attributes that might have been returned with a range= specifier.
 * It has a single "public" method -- {@link RangeAttributeParser#parseResult}.
 * It exposes two events: "error" and "done". The *done* event will be fired
 * when **all** pages of a paged search result have been retreived.
 *
 * @private
 * @param {object} searcher An instance of {@link Searcher} that is performing
 * the queries.
 */
function RangeAttributeParser (searcher) {
  this.searcher = searcher
  this.results = new Map()

  events.EventEmitter.call(this)
}
util.inherits(RangeAttributeParser, events.EventEmitter)

RangeAttributeParser.prototype.getResults = function getResults () {
  const results = []
  Array.from(this.results.values()).forEach(v => results.push(v.value()))
  return results
}

/**
 * Give it a search result that *might* have some attributes with ranges and
 * it'll recursively retrieve **all** of the values for said attributes. It
 * fires the `done` and `error` events appropriately.
 *
 * @param {object} result An LDAP search result.
 */
RangeAttributeParser.prototype.parseResult = function parseResult (result) {
  log.trace('parsing result for range attributes: %j', result)

  const _result = (this.results.has(result.dn))
    ? this.results.get(result.dn)
    : new Result(result)
  this.results.set(result.dn, _result)
  if (!RangeAttribute.hasRangeAttributes(result)) {
    this.emit('done', this.getResults())
    return
  }

  const rangeAttributes = RangeAttribute.getRangeAttributes(result)
  if (rangeAttributes.length === 0) {
    this.emit('done', this.getResults())
    return
  }

  let queryAttributes = []
  rangeAttributes.forEach((attr) => {
    const attrName = attr.attributeName
    if (!_result.rangeAttributes.has(attrName)) {
      _result.rangeAttributes.set(attrName, attr)
    }
    if (!_result.rangeAttributeResults.has(attrName)) {
      _result.rangeAttributeResults.set(attrName, [])
    }

    // update the attribute result accumulator with the new page of values
    const currRangeName = attr.toString()
    const attrResults = _result.rangeAttributeResults.get(attrName)
    const newResults = [].concat(attrResults, result[currRangeName])
    _result.rangeAttributeResults.set(attrName, newResults)

    // advance the query
    const nextAttr = attr.next()
    _result.rangeAttributes.set(attrName, nextAttr)
    delete _result.originalResult[currRangeName]
    if (nextAttr) {
      const nextRangeName = _result.rangeAttributes.get(attrName).toString()
      if (nextRangeName !== currRangeName) {
        queryAttributes.push(nextRangeName)
      }
    }
  })

  if (queryAttributes.length === 0) {
    // we have reached then end of the pages and have queried the last page
    this.emit('done', this.getResults())
    return
  }

  const rangeKeys = Array.from(_result.rangeAttributes.keys())
  queryAttributes = queryAttributes.concat(
    this.searcher.query.attributes.filter(a => rangeKeys.indexOf(a) === -1)
  )
  const filter = `(distinguishedName=${parseDistinguishedName(result.dn)})`
  const query = {
    filter: filter,
    attributes: queryAttributes,
    scope: this.searcher.query.scope
  }

  this.searcher.rangeSearch(query, (err, result) => {
    if (err) {
      this.emit('error', err)
      return
    }
    this.parseResult(result)
  })
}
