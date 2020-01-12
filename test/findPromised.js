'use strict'
/* eslint-env node, mocha */
/* eslint-disable no-unused-expressions */

const expect = require('chai').expect
const ActiveDirectory = require('../index').promiseWrapper
const config = require('./config')

let server = require('./mockServer')

describe('Promised find Method', function () {
  let ad
  const settings = require('./settings').find
  const timeout = 6000 // The timeout in milliseconds before a test is considered failed.

  before(function (done) {
    server(function (s) {
      ad = new ActiveDirectory(config)
      server = s
      done()
    })
  })

  describe('#find()', function () {
    settings.queries.forEach(function (query) {
      const userCount = query.results.users.length
      const groupCount = query.results.groups.length
      const otherCount = query.results.other.length
      const _query = (query.query.filter) ? query.query.filter : query.query
      it(`should return ${userCount} users, ${groupCount} groups, ${otherCount} other for query '${_query}'`, function (done) {
        this.timeout(timeout)

        ad.find(_query)
          .then((results) => {
            expect(results).to.not.be.null;

            ['users', 'groups', 'other'].forEach((key) => {
              const expectedResults = query.results[key]
              const actualResults = results[key]

              expect(actualResults.length).to.equal(expectedResults.length)

              const cns = actualResults.map((result) => {
                return result.cn
              })
              expectedResults.forEach((expectedResult) => {
                expect(cns.filter((cn) => {
                  return cn
                      .toLowerCase()
                      .indexOf(expectedResult.toLowerCase()) !== -1
                }).length)
                  .to.equal(1)
              })
            })

            done()
          })
          .catch(done)
      })
    })

    it('should return default query attributes when not specified', function (done) {
      const defaultAttributes = {
        groups: ad.defaultAttributes.group,
        users: ad.defaultAttributes.user
      }
      defaultAttributes.other = Array.from(new Set(
        [].concat(defaultAttributes.groups, defaultAttributes.users)
      ))

      const query = settings.queries[0]
      ad.find(query.query)
        .then((results) => {
          expect(results).to.not.be.null;

          ['users', 'groups', 'other'].forEach((key) => {
            const keyAttributes = defaultAttributes[key]
            results[key].forEach((result) => {
              const attributes = Object.keys(result)
              expect(attributes.length).to.be.lte(keyAttributes.length)
              attributes.forEach((attribute) => {
                expect(keyAttributes).to.contain(attribute)
              })
            })
          })

          done()
        })
        .catch(done)
    })
  })

  describe('#find(opts)', function () {
    it('should include groups/membership groups and users if opts.includeMembership[] = [ \'all\' ]', function (done) {
      this.timeout(timeout)

      const query = settings.queries[0]
      const opts = {
        includeMembership: [ 'all' ],
        filter: query.query
      }
      ad.find(opts)
        .then((results) => {
          expect(results).to.not.be.null

          results['users'].forEach((user) => {
            expect(user.groups).to.exist
          })

          results['groups'].forEach((group) => {
            expect(group.groups).to.exist
          })

          results['other'].forEach((other) => {
            expect(other.groups).to.not.exist
          })

          done()
        })
        .catch(done)
    })

    it('should include groups/membership for groups if opts.includeMembership[] = [ \'group\' ]', function (done) {
      this.timeout(timeout)

      const query = settings.queries[0]
      const opts = {
        includeMembership: [ 'group' ],
        filter: query.query
      }
      ad.find(opts)
        .then((results) => {
          expect(results).to.not.be.null

          results['groups'].forEach((group) => {
            expect(group.groups).to.exist
          });

          ['users', 'other'].forEach((key) => {
            const items = results[key]
            items.forEach((item) => {
              expect(item.groups).to.not.exist
            })
          })

          done()
        })
    })

    it('should include groups/membership for users if opts.includeMembership[] = [ \'user\' ]', function (done) {
      this.timeout(timeout)

      const query = settings.queries[0]
      const opts = {
        includeMembership: [ 'user' ],
        filter: query.query
      }
      ad.find(opts)
        .then((results) => {
          expect(results).to.not.be.null

          results['users'].forEach((user) => {
            expect(user.groups).to.exist
          });

          ['groups', 'other'].forEach((key) => {
            const items = results[key]
            items.forEach((item) => {
              expect(item.groups).to.not.exist
            })
          })

          done()
        })
    })

    it('should not include groups/membership if opts.includeMembership disabled', function (done) {
      const query = settings.queries[0]
      const opts = {
        includeMembership: false,
        filter: query.query
      }
      ad.find(opts)
        .then((results) => {
          expect(results).to.not.be.null;

          ['users', 'groups', 'other'].forEach((key) => {
            const items = results[key]
            items.forEach((item) => {
              expect(item.groups).to.not.exist
            })
          })

          done()
        })
    })

    it('should return only requested attributes', function (done) {
      this.timeout(timeout)
      const query = settings.queries[0]
      const opts = {
        attributes: [ 'cn' ],
        filter: query.query
      }
      ad.find(opts)
        .then((results) => {
          expect(results).to.not.be.null;

          ['users', 'groups', 'other'].forEach((key) => {
            results[key].forEach((result) => {
              const keys = Object.keys(result)
              expect(keys.length).to.be.lte(opts.attributes.length)
              if (keys.length === opts.attributes.length) {
                expect(keys).to.deep.equal(opts.attributes)
              }
            })
          })

          done()
        })
    })
  })
})
