'use strict'

/**
 * Represents an ActiveDirectory user account.
 *
 * @private
 * @param {object} [properties] The properties to assign to the newly created item.
 * @returns {User}
 */
function User (properties) {
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

/**
 * Checks to see if the user is the member of the specified group.
 *
 * @param {string} group The name of the group to check for membership.
 * @returns {boolean}
 */
User.prototype.isMemberOf = function isMemberOf (group) {
  if (!group) {
    return false
  }

  const _group = group.toLowerCase()
  return this.groups.filter((g) => g.toLowerCase() === _group).length > 0
}

module.exports = User
