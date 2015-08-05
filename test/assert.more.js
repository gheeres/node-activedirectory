var _ = require('underscore');
var assert = require('assert');

/**
 * @private
 * @params {Array} expectedResults The expected results
 * @params {
 */
function equalDifference(expectedResults, actualResults, attributeName) {
  if (typeof(attributeName) === 'undefined') attributeName = 'cn';

  assert.equal(expectedResults.length, actualResults.length,
               expectedResults.length > actualResults.length ?
               'Expected item(s) not found: ' + 
                 JSON.stringify(_.difference(_.map(expectedResults, function(item) { 
                                               return((item[attributeName] || item).toLowerCase()); 
                                             }), 
                                             _.map(actualResults, function(item) { 
                                              return((item[attributeName] || item).toLowerCase()); 
                                             })
                                            )) :
               'Unexpected items(s) found: ' +
                 JSON.stringify(_.difference(_.map(actualResults, function(item) { 
                                              return((item[attributeName] || item).toLowerCase()); 
                                             }),
                                             _.map(expectedResults, function(item) { 
                                               return((item[attributeName] || item).toLowerCase()); 
                                             })
                                            ))
              );
  (actualResults || []).forEach(function(actualItem) {
    var lowercaseItem = (actualItem[attributeName] || actualItem).toLowerCase();
    assert(_.any(expectedResults || [], function(expectedItem) {
      return(lowercaseItem === (expectedItem[attributeName] || expectedItem).toLowerCase());
    }));
  });
}

module.exports = _.extend(assert, {
  equalDifference: equalDifference
});
