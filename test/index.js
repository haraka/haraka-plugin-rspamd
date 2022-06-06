'use strict';

const assert       = require('assert')

const fixtures     = require('haraka-test-fixtures');
const connection   = fixtures.connection;

function _set_up (done) {
  this.plugin = new fixtures.plugin('rspamd');
  this.plugin.register();
  this.connection = connection.createConnection();
  this.connection.transaction = fixtures.transaction.createTransaction()
  // this.connection.init_transaction();

  done();
}

describe('register', function () {

  beforeEach(_set_up)

  it('loads the rspamd plugin', function (done) {
    assert.equal('rspamd', this.plugin.name);
    done();
  })

  it('register loads rspamd.ini', function (done) {
    this.plugin.register();
    assert.ok(this.plugin.cfg);
    assert.equal(true, this.plugin.cfg.reject.spam);
    assert.ok(this.plugin.cfg.header.bar);
    done();
  })
})

describe('add_headers', function () {

  beforeEach(_set_up)

  it('add_headers exists as function', function (done) {
    // console.log(this.plugin.cfg);
    assert.equal('function', typeof this.plugin.add_headers);
    done();
  })

  it('adds a header to a message with positive score', function (done) {
    const test_data = {
      score: 1.1,
      symbols: {
        FOO: {
          name: 'FOO',
          score: 0.100000,
          description: 'foo',
          options: ['foo', 'bar'],
        },
        BAR: {
          name: 'BAR',
          score: 1.0,
          description: 'bar',
        }
      }
    };
    this.plugin.cfg.main.add_headers = 'always';
    this.plugin.add_headers(this.connection, test_data);
    assert.deepEqual(this.connection.transaction.header.headers['x-rspamd-score'], [ '1.1' ]);
    assert.deepEqual(this.connection.transaction.header.headers['x-rspamd-bar'], ['+']);
    assert.deepEqual(this.connection.transaction.header.headers['x-rspamd-report'], ['FOO(0.1) BAR(1)']);
    done();
  })

  it('adds a header to a message with negative score', function (done) {
    const test_data = {
      score: -1
    };
    this.plugin.cfg.main.add_headers = 'always';
    this.plugin.add_headers(this.connection, test_data);
    // console.log(this.connection.transaction.header);
    assert.deepEqual(this.connection.transaction.header.headers['x-rspamd-score'], ['-1']);
    assert.deepEqual(this.connection.transaction.header.headers['x-rspamd-bar'], ['-']);
    done();
  })
})


describe('wants_headers_added', function () {

  beforeEach(_set_up)

  it('wants no headers when add_headers=never', function (done) {
    this.plugin.cfg.main.add_headers='never';
    assert.equal(
      this.plugin.wants_headers_added({ action: 'add header' }),
      false
    );
    done();
  })

  it('always wants no headers when add_headers=always', function (done) {
    this.plugin.cfg.main.add_headers='always';
    assert.equal(
      this.plugin.wants_headers_added({ action: 'beat it' }),
      true
    );
    done();
  })

  it('wants headers when rspamd response indicates, add_headers=sometimes', function (done) {
    this.plugin.cfg.main.add_headers='sometimes';
    assert.equal(
      this.plugin.wants_headers_added({ action: 'add header' }),
      true
    );
    assert.equal(
      this.plugin.wants_headers_added({ action: 'brownlist' }),
      false
    );
    done();
  })
})

describe('parse_response', function () {
  beforeEach(_set_up)

  it('returns undef on empty string', function (done) {
    // console.log(this.connection.transaction);
    assert.equal(
      this.plugin.parse_response('', this.connection),
      undefined
    );
    done();
  })

  it('returns undef on empty object', function (done) {
    assert.equal(
      this.plugin.parse_response('{}', this.connection),
      undefined
    );
    done();
  })
})


describe('should_check', function () {

  beforeEach(function (done) {
    this.plugin = new fixtures.plugin('rspamd');
    this.plugin.register();
    this.connection = connection.createConnection();
    this.connection.init_transaction();

    // init defaults
    this.plugin.cfg.check.local_ip = false;
    this.plugin.cfg.check.private_ip = false;
    this.plugin.cfg.check.authenticated = false;

    this.connection.remote.is_local = false;
    this.connection.remote.is_private = false;
    this.connection.notes.auth_user = undefined;

    done()
  })

  it('checks authenticated', function (done) {
    this.connection.notes.auth_user = "username";
    this.plugin.cfg.check.authenticated = true;

    assert.equal(this.plugin.should_check(this.connection), true);
    done();
  })
  it('skips authenticated', function (done) {
    this.connection.notes.auth_user = "username";
    this.plugin.cfg.check.authenticated = false;

    assert.equal(this.plugin.should_check(this.connection), false);
    done();
  })
  it('skips relaying', function (done) {
    this.connection.relaying = true;
    this.plugin.cfg.check.relay = false;

    assert.equal(this.plugin.should_check(this.connection), false);
    done();
  })
  it('checks not relaying', function (done) {
    this.connection.relaying = false;
    this.plugin.cfg.check.relay = false;

    assert.equal(this.plugin.should_check(this.connection), true);
    done();
  })
  it('checks relaying when enabled', function (done) {
    this.connection.relaying = true;
    this.plugin.cfg.check.relay = true;

    assert.equal(this.plugin.should_check(this.connection), true);
    done();
  })
  it('checks local IP', function (done) {
    this.connection.remote.is_local = true;
    this.plugin.cfg.check.local_ip = true;

    assert.equal(this.plugin.should_check(this.connection), true);
    done();
  })
  it('skips local IP', function (done) {
    this.connection.remote.is_local = true;
    this.plugin.cfg.check.local_ip = false;

    assert.equal(this.plugin.should_check(this.connection), false);
    done();
  })
  it('checks private IP', function (done) {
    this.connection.remote.is_private = true;
    this.plugin.cfg.check.private_ip = true;

    assert.equal(this.plugin.should_check(this.connection), true);
    done();
  })
  it('skips private IP', function (done) {
    this.connection.remote.is_private = true;
    this.plugin.cfg.check.private_ip = false;

    assert.equal(this.plugin.should_check(this.connection), false);
    done();
  })
  it('checks public ip', function (done) {
    assert.equal(this.plugin.should_check(this.connection), true);
    done();
  })
  it('skip localhost if check.local_ip = false and check.private_ip = true', function (done) {
    this.connection.remote.is_local = true;
    this.connection.remote.is_private = true;

    this.plugin.cfg.check.local_ip = false;
    this.plugin.cfg.check.private_ip = true;

    assert.equal(this.plugin.should_check(this.connection), false);
    done();
  })
  it('checks localhost if check.local_ip = true and check.private_ip = false', function (done) {
    this.connection.remote.is_local = true;
    this.connection.remote.is_private = true;

    this.plugin.cfg.check.local_ip = true;
    this.plugin.cfg.check.private_ip = false;

    assert.equal(this.plugin.should_check(this.connection), true);
    done();
  })
})
