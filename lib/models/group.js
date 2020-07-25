'use strict'

/**
 * Represents an ActiveDirectory group
 *
 * @private
 * @param {object} [properties] The properties to assign to the newly created item.
 * @returns {Group}
 */
function Group (properties) {
  if (!properties) {
    return this
  }

  for (const prop of Object.getOwnPropertyNames(properties)) {
    Object.defineProperty(this, prop, {
      value: properties[prop],
      enumerable: true,
      writable: true
    })
  }
}

module.exports = Group
