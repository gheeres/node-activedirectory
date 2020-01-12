'use strict'

// https://msdn.microsoft.com/en-us/library/cc223242.aspx
// [attribute];range=[low]-[high]
// matching: 1 = name, 2 = low, 3 = high
const rangeRegex = /^([^;]+);range=(\d+)-([\d*]+)$/i

/**
 * Represents an attribute wherein a query has been limited to a spcific range.
 *
 * @private
 * @constructor
 * @param {string|object} [null] attribute The actual attribute name. May also
 * contain a full range retrieval specifier for parsing
 * (i.e. [attribute];range=[low]-[high]). Optionally an object can be specified.
 * @returns {RangeAttribute}
 */
function RangeAttribute (attribute) {
  if (attribute && ((typeof attribute) === 'string')) {
    return RangeAttribute.fromString(attribute)
  }

  this.attributeName = null
  this.low = null
  this.high = null
}

/**
 * Gets the next range retrieval specifier for a query.
 *
 * @private
 * @returns {RangeAttribute}
 */
RangeAttribute.prototype.next = function next () {
  if ((this.high !== null) && (this.high !== this.low)) {
    const low = this.low
    const high = this.high

    this.low = high + 1
    this.high = high + (high - low) + 1
    if (low === 0) {
      this.high += 1
    }

    return this
  }
  return null
}

/**
 * Checks to see if the range specifier has been exhausted or completed.
 *
 * @private
 * @returns {boolean}
 */
RangeAttribute.prototype.isComplete = function isComplete () {
  return ((this.high == null) || ((typeof this.high) === 'undefined'))
}

/**
 * Gets the string representation of the range retrieval specifier.
 *
 * @private
 * @returns {string}
 */
RangeAttribute.prototype.toString = function toString () {
  return (
    this.attributeName + ';range=' +
    this.low + '-' + (this.high ? this.high : '*')
  )
}

/**
 * Parses the range retrieval specifier into an object.
 *
 * @private
 * @param {string} str The range retrieval specifier to parse.
 * @returns {RangeAttribute}
 */
RangeAttribute.fromString = function fromString (str) {
  const match = rangeRegex.exec(str)

  const rrsa = new RangeAttribute()
  rrsa.attributeName = match[1]
  rrsa.low = parseInt(match[2], 10)
  rrsa.high = parseInt(match[3], 10) || null
  return rrsa
}

/**
 * Retrieves all of the attributes which have range attributes specified.
 *
 * @private
 * @static
 * @param {object} entry SearchEntry to extract the range retrieval attributes from.
 * @returns {Array}
 */
RangeAttribute.getRangeAttributes = function getRangeAttributes (entry) {
  const attributes = []
  for (const attribute of Object.keys(entry)) {
    if (RangeAttribute.isRangeAttribute(attribute)) {
      const range = new RangeAttribute(attribute)
      attributes.push(range)
    }
  }
  return attributes
}

/**
 * Checks to see if the specified attribute is a range retrieval attribute.
 *
 * @private
 * @static
 * @param {string} attribute The attribute to inspect.
 * @returns {boolean}
 */
RangeAttribute.isRangeAttribute = function isRangeAttribute (attribute) {
  return rangeRegex.test(attribute)
}

/**
 * Checks to see if the specified object has any range retrieval attributes.
 *
 * @private
 * @static
 * @param {object} entry SearchEntry to check for range retrieval specifiers.
 * @returns {boolean}
 */
RangeAttribute.hasRangeAttributes = function hasRangeAttributes (entry) {
  return Object.keys(entry)
    .filter(entry => {
      return RangeAttribute.isRangeAttribute(entry)
    })
    .length > 0
}

module.exports = RangeAttribute
