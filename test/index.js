'use strict';

// var Address      = require('address-rfc2821');
const fixtures     = require('haraka-test-fixtures');

const connection   = fixtures.connection;

const _set_up = function (done) {

    this.plugin = new fixtures.plugin('rspamd');
    this.plugin.register();
    this.connection = connection.createConnection();
    this.connection.init_transaction();

    done();
}

exports.register = {
    setUp : _set_up,
    'loads the rspamd plugin': function (test) {
        test.expect(1);
        test.equal('rspamd', this.plugin.name);
        test.done();
    },
    'register loads rspamd.ini': function (test) {
        test.expect(2);
        this.plugin.register();
        test.ok(this.plugin.cfg);
        test.equal(true, this.plugin.cfg.reject.spam);
        test.done();
    },
}

exports.load_rspamd_ini = {
    setUp : _set_up,
    'loads rspamd.ini': function (test) {
        test.expect(1);
        this.plugin.load_rspamd_ini();
        test.ok(this.plugin.cfg.header.bar);
        test.done();
    },
}

exports.add_headers = {
    setUp : _set_up,
    'add_headers exists as function': function (test) {
        test.expect(1);
        // console.log(this.plugin.cfg);
        test.equal('function', typeof this.plugin.add_headers);
        // test.ok(!this.plugin.score_too_high(this.connection, {score: 5}));
        test.done();
    },
    'adds a header to a message with positive score': function (test) {
        test.expect(3);
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
        test.equal(this.connection.transaction.header.headers['X-Rspamd-Score'], '1.1');
        test.equal(this.connection.transaction.header.headers['X-Rspamd-Bar'], '+');
        test.equal(this.connection.transaction.header.headers['X-Rspamd-Report'], 'FOO(0.1) BAR(1)');
        test.done();
    },
    'adds a header to a message with negative score': function (test) {
        test.expect(2);
        const test_data = {
            score: -1
        };
        this.plugin.cfg.main.add_headers = 'always';
        this.plugin.add_headers(this.connection, test_data);
        // console.log(this.connection.transaction.header);
        test.equal(this.connection.transaction.header.headers['X-Rspamd-Score'], '-1');
        test.equal(this.connection.transaction.header.headers['X-Rspamd-Bar'], '-');
        test.done();
    }
}

exports.wants_headers_added = {
    setUp : _set_up,
    'wants no headers when add_headers=never': function (test) {
        test.expect(1);
        this.plugin.cfg.main.add_headers='never';
        test.equal(
            this.plugin.wants_headers_added({ action: 'add header' }),
            false
        );
        test.done();
    },
    'always wants no headers when add_headers=always': function (test) {
        test.expect(1);
        this.plugin.cfg.main.add_headers='always';
        test.equal(
            this.plugin.wants_headers_added({ action: 'beat it' }),
            true
        );
        test.done();
    },
    'wants headers when rspamd response indicates, add_headers=sometimes': function (test) {
        test.expect(2);
        this.plugin.cfg.main.add_headers='sometimes';
        test.equal(
            this.plugin.wants_headers_added({ action: 'add header' }),
            true
        );
        test.equal(
            this.plugin.wants_headers_added({ action: 'brownlist' }),
            false
        );
        test.done();
    }
}

exports.parse_response = {
    setUp : _set_up,
    'returns undef on empty string': function (test) {
        test.expect(1);
        // console.log(this.connection.transaction);
        test.equal(
            this.plugin.parse_response('', this.connection),
            undefined
        );
        test.done();
    },
    'returns undef on empty object': function (test) {
        test.expect(1);
        test.equal(
            this.plugin.parse_response('{}', this.connection),
            undefined
        );
        test.done();
    },
}

function _check_setup (done) {

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
}

exports.should_check = {
    setUp : _check_setup,
    'checks authenticated': function (test) {
        this.connection.notes.auth_user = "username";
        this.plugin.cfg.check.authenticated = true;

        test.expect(1);
        test.equal(this.plugin.should_check(this.connection), true);
        test.done();
    },
    'skips authenticated': function (test) {
        this.connection.notes.auth_user = "username";
        this.plugin.cfg.check.authenticated = false;

        test.expect(1);
        test.equal(this.plugin.should_check(this.connection), false);
        test.done();
    },
    'skips relaying': function (test) {
        this.connection.relaying = true;
        this.plugin.cfg.check.relay = false;

        test.expect(1);
        test.equal(this.plugin.should_check(this.connection), false);
        test.done();
    },
    'checks not relaying': function (test) {
        this.connection.relaying = false;
        this.plugin.cfg.check.relay = false;

        test.expect(1);
        test.equal(this.plugin.should_check(this.connection), true);
        test.done();
    },
    'checks relaying when enabled': function (test) {
        this.connection.relaying = true;
        this.plugin.cfg.check.relay = true;

        test.expect(1);
        test.equal(this.plugin.should_check(this.connection), true);
        test.done();
    },
    'checks local IP': function (test) {
        this.connection.remote.is_local = true;
        this.plugin.cfg.check.local_ip = true;

        test.expect(1);
        test.equal(this.plugin.should_check(this.connection), true);
        test.done();
    },
    'skips local IP': function (test) {
        this.connection.remote.is_local = true;
        this.plugin.cfg.check.local_ip = false;

        test.expect(1);
        test.equal(this.plugin.should_check(this.connection), false);
        test.done();
    },
    'checks private IP': function (test) {
        this.connection.remote.is_private = true;
        this.plugin.cfg.check.private_ip = true;

        test.expect(1);
        test.equal(this.plugin.should_check(this.connection), true);
        test.done();
    },
    'skips private IP': function (test) {
        this.connection.remote.is_private = true;
        this.plugin.cfg.check.private_ip = false;

        test.expect(1);
        test.equal(this.plugin.should_check(this.connection), false);
        test.done();
    },
    'checks public ip': function (test) {
        test.expect(1);
        test.equal(this.plugin.should_check(this.connection), true);
        test.done();
    },
    'skip localhost if check.local_ip = false and check.private_ip = true': function (test) {
        this.connection.remote.is_local = true;
        this.connection.remote.is_private = true;

        this.plugin.cfg.check.local_ip = false;
        this.plugin.cfg.check.private_ip = true;

        test.expect(1);
        test.equal(this.plugin.should_check(this.connection), false);
        test.done();
    },
    'checks localhost if check.local_ip = true and check.private_ip = false': function (test) {
        this.connection.remote.is_local = true;
        this.connection.remote.is_private = true;

        this.plugin.cfg.check.local_ip = true;
        this.plugin.cfg.check.private_ip = false;

        test.expect(1);
        test.equal(this.plugin.should_check(this.connection), true);
        test.done();
    },
}