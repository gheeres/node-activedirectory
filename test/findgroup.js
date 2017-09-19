'use strict'
/* eslint-env node, mocha */
/* eslint-disable no-unused-expressions */

const expect = require('chai').expect
const ActiveDirectory = require('../index')
const config = require('./config')

let server = require('./mockServer')

describe('findGroup Method', function () {
  let ad
  const settings = require('./settings').findGroup

  before(function (done) {
    server(function (s) {
      ad = new ActiveDirectory(config)
      server = s
      done()
    })
  })

  describe('#findGroup()', function () {
    [ 'cn', 'dn' ].forEach((groupAttribute) => {
      const groupName = settings.groupName[groupAttribute]
      it(`should return user for (${groupAttribute} ${groupName}`, function (done) {
        ad.findGroup(settings.groupName[groupAttribute], function (err, group) {
          expect(err).to.be.null
          expect(group).to.not.be.null
          done()
        })
      })
    })

    it('should return undefined if the group doesn\'t exist', function (done) {
      ad.findGroup('!!!NON-EXISTENT GROUP!!!', function (err, group) {
        expect(err).to.not.be.null
        expect(group).to.be.undefined
        done()
      })
    })

    it('should return default group attributes when not specified', function (done) {
      const defaultAttributes = ActiveDirectory.defaultAttributes.group
      ad.findGroup(settings.groupName.dn, function (err, group) {
        expect(err).to.be.null
        expect(group).to.not.be.null

        const attributes = Object.keys(group)
        expect(attributes.length).to.be.lte(defaultAttributes.length)
        expect(attributes).to.have.any.members(defaultAttributes)
        done()
      })
    })
  })

  describe('#findGroup(opts)', function () {
    it('should use the custom opts.filter if provided', function (done) {
      const opts = {
        filter: settings.opts.custom
      }
      const groupName = settings.groupName.dn
      ad.findGroup(opts, groupName, function (err, group) {
        expect(err).to.be.null
        expect(group).to.not.be.null
        expect(group.dn.toLowerCase()).to.not.equal(groupName.toLowerCase())
        done()
      })
    })

    it('should include groups/membership if opts.includeMembership[] = [ \'all\' ]', function (done) {
      const opts = {
        includeMembership: [ 'all' ]
      }
      ad.findGroup(opts, settings.groupName.dn, function (err, group) {
        expect(err).to.be.null
        expect(group).to.not.be.null
        const cns = group.groups.map((group) => {
          return group.cn
        })
        expect(cns).to.deep.include.members(settings.groups)
        done()
      })
    })

    it('should include groups/membership if opts.includeMembership[] = [ \'group\' ]', function (done) {
      const opts = {
        includeMembership: [ 'group' ]
      }
      ad.findGroup(opts, settings.groupName.dn, function (err, group) {
        expect(err).to.be.null
        expect(group).to.not.be.null
        const cns = group.groups.map((group) => {
          return group.cn
        })
        expect(cns).to.deep.include.members(settings.groups)
        done()
      })
    })

    it('should return expected groups/membership if opts.includeMembership enabled', function (done) {
      const opts = {
        includeMembership: [ 'group', 'all' ]
      }
      ad.findGroup(opts, settings.groupName.dn, function (err, group) {
        expect(err).to.be.null
        expect(group).to.not.be.null
        const cns = group.groups.map((group) => {
          return group.cn
        })
        expect(cns).to.deep.include.members(settings.groups)
        done()
      })
    })

    it('should return only the first group if more than one result returned', function (done) {
      const opts = {
        filter: settings.opts.multipleFilter
      }
      ad.findGroup(opts, '' /* ignored since we're setting our own filter */, function (err, group) {
        expect(err).to.be.null
        expect(group).to.not.be.null
        expect(Array.isArray(group)).to.be.false
        done()
      })
    })

    it('should return only requested attributes', function (done) {
      const opts = {
        attributes: [ 'createdTimestamp' ]
      }
      ad.findGroup(opts, settings.groupName.dn, function (err, group) {
        expect(err).to.be.null
        expect(group).to.not.be.null

        const keys = Object.keys(group)
        expect(keys.length).to.equal(opts.attributes.length)
        if (keys.length === opts.attributes.length) {
          expect(keys).to.have.any.members(opts.attributes)
        }
        done()
      })
    })
  })
})
