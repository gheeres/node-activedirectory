/** 
 * Represents an ActiveDirectory group
 *
 * @private
 * @param {Object} [properties] The properties to assign to the newly created item.
 * @returns {Group}
 */
var Group = function(properties) {
  for (var property in (properties || {})) {
    if (Array.prototype.hasOwnProperty.call(properties, property)) {
      this[property] = properties[property];
    }
  }
}

module.exports = Group;
