var _ = require('underscore');

// [attribute];range=[low]-[high]
// matching: 1 = name, 2 = low, 3 = high
var pattern = '^([^;]+);range=(\\d+)-(.+)?$'; 

/**
 * Parses the range retrieval specifier into an object.
 * 
 * @private
 * @param {String} range The range retrieval specifier to parse.
 * @returns {RangeRetrievalSpecifier}
 */
function parseRangeRetrievalSpecifierAttribute(attribute) {
  var re = new RegExp(pattern, 'i');
  var match = re.exec(attribute);
  return({
    attributeName: match[1],
    low: parseInt(match[2]),
    high: parseInt(match[3]) || null
  });
};

/**
 * Multi-valued attribute range retreival specifier.
 *
 * @private
 * @constructor
 * @param {String|Object} attribute The actual attribute name. May also contain a full range retrieval specifier for parsing. (i.e. [attribute];range=[low]-[high]). Optionally an object can be specified.
 * @returns {RangeRetrievalSpecifierAttribute}
 */
var RangeRetrievalSpecifierAttribute = function(attribute) {
  if (this instanceof RangeRetrievalSpecifierAttribute) {
    if (! attribute) throw new Error('No attribute provided to create a range retrieval specifier.');
    if (typeof(attribute) === 'string') {
      attribute = parseRangeRetrievalSpecifierAttribute(attribute);
    }

    for(var property in attribute) {
      if (Array.prototype.hasOwnProperty.call(attribute, property)) {
        this[property] = attribute[property];
      }
    }
  }
  else {
    return(new RangeRetrievalSpecifierAttribute(attribute));
  }
}

/** 
 * Gets the next range retrieval specifier for a query.
 *
 * @private
 * @returns {String}
 */
RangeRetrievalSpecifierAttribute.prototype.next = function next() {
  var self = this;

  if ((self.high != null) && (self.high != self.low)) {
    var low = self.low;
    var high = self.high;

    self.low = high + 1;
    self.high = high + (high - low) + 1;
    return(this);
  }
  return(null);
}

/** 
 * Checks to see if the range specifier has been exhausted or completed.
 *
 * @private
 * @returns {Boolean}
 */
RangeRetrievalSpecifierAttribute.prototype.isComplete = function isComplete() {
  var self = this;
  return((self.high == null) || (typeof(self.high) === 'undefined'));
}

/** 
 * Gets the string representation of the range retrieval specifier.
 *
 * @private
 * @returns {String}
 */
RangeRetrievalSpecifierAttribute.prototype.toString = function toString() {
  var self = this;

  return(self.attributeName + ';range=' + self.low + '-' + (self.high ? self.high : '*'));
}

/**
 * Retrieves all of the attributes which have range attributes specified.
 * 
 * @private
 * @static
 * @param {Object} item The value to extract the range retrieval attributes from.
 * @returns {Array[RangeRetrievalSpecifierAttribute]}
 */
RangeRetrievalSpecifierAttribute.prototype.getRangeAttributes = function getRangeAttributes(item) {
  var attributes = [];
  for(var attribute in (item || {})) {
    if (RangeRetrievalSpecifierAttribute.prototype.isRangeAttribute(attribute)) {
      var range = new RangeRetrievalSpecifierAttribute(attribute);
      attributes.push(range);
    }
  }
  return(attributes.length > 0 ? attributes : null);
};

/**
 * Checks to see if the specified attribute is a range retrieval attribute.
 * 
 * @private
 * @static
 * @param {String} attribute The attribute to inspect.
 * @returns {Boolean}
 */
RangeRetrievalSpecifierAttribute.prototype.isRangeAttribute = function isRangeAttribute(attribute) {
  var re = new RegExp(pattern, 'i');
  return(re.test(attribute));
};

/**
 * Checks to see if the specified object has any range retrieval attributes.
 * 
 * @private
 * @static
 * @param {Object} item The value to check for range retrieval specifiers.
 * @returns {Boolean}
 */
RangeRetrievalSpecifierAttribute.prototype.hasRangeAttributes = function hasRangeAttributes(item) {
  return(_.any(_.keys(item || {}), function(attribute) {
    return(RangeRetrievalSpecifierAttribute.prototype.isRangeAttribute(attribute));
  }));
};

module.exports = RangeRetrievalSpecifierAttribute;
