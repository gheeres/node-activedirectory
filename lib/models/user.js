var _ = require('underscore');

/** 
 * Represents an ActiveDirectory user account.
 *
 * @private
 * @param {Object} [properties] The properties to assign to the newly created item.
 * @returns {User}
 */
var User = function(properties) {
  if (this instanceof User) {
    for (var property in (properties || {})) {
      if (Array.prototype.hasOwnProperty.call(properties, property)) {
        this[property] = properties[property];
      }
    }
  }
  else {
   return(new User(properties));
  }
};

/**
 * Checks to see if the user is the member of the specified group.
 *
 * @param {String} group The name of the group to check for membership.
 * @returns {Boolean}
 */
User.prototype.isMemberOf = function isMemberOf(group) {
  if (! group) return(false);

  group = (group || '').toLowerCase();
  return(_.any(this.groups || [], function(item) {
    return (((item || {}).cn || '').toLowerCase() === group);
  }));
};

module.exports = User;
