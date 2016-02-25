'use strict';

const url = require('url');
const ldap = require('ldapjs');
const utils = require('./utilities');

let ad;
let log;
let parseRangeAttributes;

function isReferralAllowed(referralUri) {
  if (ad.defaultReferrals.enabled === false || !referralUri) {
    return false;
  }

  let result = true;
  for (let excludePattern of ad.defaultReferrals.exclude) {
    const regex = new RegExp(excludePattern, 'i');
    if (regex.test(referralUri)) {
      result = false;
      break;
    }
  }

  return result;
}

/**
 * @property {string} baseDN Where in the tree to start searches.
 * @property {function} callback A function to invoke when the search has
 * completed. This method must accept an error and a result, in that order.
 * @property {object} opts All of the options relevant to an
 * {@link ActiveDirectory} instance. It must include an `opts` property that
 * represents that is an {@link LDAPQueryParameters}.
 * @private
 * @typedef {object} SearcherOptions
 */

/**
 * An interface for performing searches against an Active Directory database.
 * It handles ranged results, finding deleted items, and following referrals.
 *
 * @private
 * @param {SearcherOptions} opts
 * @constructor
 */
function Searcher(opts) { // jshint -W071
  this.baseDN = opts.baseDN;
  this.callback = opts.callback;
  this.opts = opts;
  this.ldapOpts = utils.getLdapClientOpts(this.opts);
  this.query = this.opts.opts;

  this.results = [];
  this.pendingReferrals = new Set();
  this.pendingRangeRetrievals = 0;
  this.searchComplete = false;

  this.client = utils.createClient(ad.url || ad.opts.url, this.ldapOpts, ad);

  this.controls = this.opts.controls || [];

  // Add paging results control by default if not already added.
  const pagedControls = this.controls.filter(
    (control) => control instanceof ldap.PagedResultsControl
  );
  if (pagedControls.length === 0) {
    log.debug('Adding PagedResultControl to search (%s) with filter "%s" for %j',
              this.baseDN,
              this.query.filter,
              (this.query.attributes) ? this.opts.attributes : '[*]'
    );
    this.controls.push(new ldap.PagedResultsControl({
      value: { size: ad.pageSize }
    }));
  }

  if (this.opts.includeDeleted) {
    const deletedControls = this.controls.filter(
      (control) => control.type === '1.2.840.113556.1.4.417'
    );
    if (deletedControls.length === 0) {
      log.debug('Adding ShowDeletedOidControl(1.2.840.113556.1.4.417) to search (%s) with filter "%s" for %j',
                this.baseDN,
                this.query.filter,
                (this.query.attributes) ? this.query.attributes : '[*]'
      );
      this.controls.push(new ldap.Control({
        type: '1.2.840.113556.1.4.417',
        criticality: true
      }));
    }
  }
}

/**
 * The only method you should need to invoke. It uses the information parsed
 * during construction to construct the query and submit it to the server. Once
 * the query has completed, or an error occurs, the callback you specified
 * during construction will be invoked.
 */
Searcher.prototype.search = function search() {
  log.debug('Querying active directory (%s) with filter "%s" for %j',
            this.baseDN,
            this.query.filter,
            (this.query.attributes) ? this.query.attributes : '[*]'
  );

  this.client.on('error', (err) => {
    // to handle connection errors
    this.callback(err);
  });

  this.client.search(this.baseDN, this.query, this.controls, (err, res) => {
    if (err) {
      if (this.callback) {
        this.callback(err);
      }
      return;
    }

    const errCallback = (err) => {
      if (err.name === 'SizeLimitExceededError') {
        this.onSearchEnd(res);
        return;
      }

      this.client.unbind();
      log.error(err,
                '[%s] An error occurred performing the requested LDAP search on %s (%j)',
                err.errno || 'UNKNOWN',
                this.baseDN,
                this.opts
      );
      if (this.callback) {
        this.callback(err);
      }
    };

    res.on('searchEntry', this.onSearchEntry.bind(this));
    res.on('searchReference', this.onReferralChase.bind(this));
    res.on('error', errCallback);
    res.on('end', (err) => {
      this.searchComplete = true;
      this.onSearchEnd();
    });
  });
};

/**
 * If set via the options of the query or the {@link ActiveDirectory}
 * instance, run the entry through the function. Otherwise, just feed it to
 * the parser callback.
 *
 * @param {object} entry The search entry object.
 * @param {object} raw The raw search entry object as returned from ldap.js.
 * @param {function} callback The callback to execute when complete.
 */
Searcher.prototype.entryParser = function entryParser(entry, raw, callback) {
  if (this.opts.entryParser) {
    return this.opts.entryParser(entry, raw, callback);
  } else if (ad.opts.entryParser) {
    return ad.opts.entryParser(entry, raw, callback);
  }

  return callback(entry);
};

/**
 * Invoked when the ldap.js client is returning a search entry result.
 *
 * @param {object} entry The search entry as returned by ldap.js.
 */
Searcher.prototype.onSearchEntry = function onSearchEntry(entry) {
  log.trace('onSearchEntry(%j)', entry);
  var result = entry.object;
  delete result.controls;

  // Some attributes can have range attributes (paging). Execute the query
  // again to get additional items.
  const parserCallback = (result) => {
    if (result) {
      this.results.push(result);
    }
    if (this.pendingRangeRetrievals === 0 && this.searchComplete) {
      this.onSearchEnd();
    }
  };
  this.pendingRangeRetrievals += 1;
  parseRangeAttributes(result, this, (err, item) => {
    this.pendingRangeRetrievals -= 1;

    let _item = item;
    if (err) {
      _item = entry.object;
    }
    this.entryParser(_item, entry.raw, parserCallback);
  });
};

/**
 * Used to handle referrals, if they are enabled.
 *
 * @param {object} referral A referral object that has a `uris` property.
 */
Searcher.prototype.onReferralChase = function onReferralChase(referral) {
  referral.uris.forEach((uri) => {
    if (!isReferralAllowed(uri)) {
      return;
    }

    log.debug('Following LDAP referral chase at %s', uri);
    const referral = url.parse(uri);
    const referralBaseDn = (referral.pathname || '/').substring(1);
    const refSearcher = new Searcher({
      baseDN: referralBaseDn,
      opts: this.opts,
      callback: (err, res) => {
        if (err) {
          log.error(
            err,
            '[%s] An error occurred chasing the LDAP referral on %s (%j)',
            err.errno,
            referralBaseDn,
            this.opts
          );
        }
        this.removeReferral(refSearcher);
      }
    });
    this.pendingReferrals.add(refSearcher);

    refSearcher.search();
  });
};

/**
 * Invoked when the main search has completed, including any referrals.
 */
Searcher.prototype.onSearchEnd = function onSearchEnd() {
  if (this.pendingRangeRetrievals === 0 && this.pendingReferrals.size === 0) {
    this.client.unbind();
    log.info('Active directory search (%s) for "%s" returned %d entries.',
              this.baseDN,
              this.ldapOpts.filter,
              this.results.length
    );
    if (this.callback) {
      this.callback(null, this.results);
    }
  }
};

/**
 * Dequeues a referral chase client.
 *
 * @param {object} referral An instance of {@link Searcher} being used to chase
 * a referral.
 */
Searcher.prototype.removeReferral = function removeReferral(referral) {
  if (!referral) {
    return;
  }

  referral.client.unbind();
  this.pendingReferrals.delete(referral);
};

/**
 * @property {string} [scope] The type of search to perform: base, one, or sub.
 * Default: base.
 * @property {string} [filter] The LDAP filter to use.
 * Default: '(objectclass=*)'
 * @property {array} [attributes] A list of entry attributes to include in the
 * result. Defaults to all attributes.
 * @property {int} [sizeLimit] The maximum number of entries to return.
 * Default: 0 (infinite)
 * @property {int} [timeLimit] The maximum number of seconds to wait for a
 * server response. Default: 10.
 * @typedef {object} LDAPQueryParameters
 */

/**
 * Wraps an instance of {@link Searcher} so as to be backward compatible with
 * the original search function.
 *
 * @private
 * @param {string} [baseDN] The optional base directory where the LDAP query is
 * to originate from. If not specified, then starts at the root.
 * @param {LDAPQueryParameters} [opts] LDAP query string parameters to execute.
 * @param {function} callback The callback to execure when completed.
 * The call back is a standard Node style callback with an error parameter and
 * a result parameter.
 */
function search(baseDN, opts, callback) { // jshint -W071
  const options = Object.assign({}, ad.opts);

  if (typeof baseDN === 'function') {
    options.baseDN = ad.baseDN;
    options.callback = baseDN;
    options.opts = {};
  } else if (typeof baseDN === 'object') {
    options.baseDN = ad.baseDN;
    options.callback = opts;
    options.opts = baseDN;
  } else if (typeof baseDN === 'string') {
    options.baseDN = baseDN;
    if (typeof opts === 'function') {
      options.callback = opts;
      options.opts = {};
    } else {
      options.callback = callback;
      options.opts = opts;
    }
  }

  const searcher = new Searcher(options);
  return searcher.search();
}

module.exports = function($ad, $log) {
  ad = $ad;
  log = $log;
  parseRangeAttributes = require('./parseRangeAttributes')($ad, $log);
  return search;
};