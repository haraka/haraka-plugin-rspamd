'use strict'

const assert = require('node:assert')
const fs = require('node:fs')
const http = require('node:http')
const https = require('node:https')
const os = require('node:os')
const path = require('node:path')
const { PassThrough } = require('node:stream')
const { afterEach, beforeEach, describe, it } = require('node:test')

const { Address } = require('@haraka/email-address')
const { makeConnection, makePlugin } = require('haraka-test-fixtures')

const _set_up = (t, done) => {
  this.plugin = makePlugin('rspamd')
  this.connection = makeConnection({ withTxn: true })
  done()
}

describe('register', () => {
  beforeEach(_set_up)

  it('loads the rspamd plugin', () => {
    assert.equal('rspamd', this.plugin.name)
  })

  it('register loads rspamd.ini', () => {
    this.plugin.register()
    assert.ok(this.plugin.cfg)
    assert.equal(true, this.plugin.cfg.reject.spam)
    assert.ok(this.plugin.cfg.header.bar)
  })
})

describe('add_headers', () => {
  beforeEach(_set_up)

  it('add_headers exists as function', () => {
    assert.equal('function', typeof this.plugin.add_headers)
  })

  it('adds a header to a message with positive score', () => {
    const test_data = {
      score: 1.1,
      symbols: {
        FOO: {
          name: 'FOO',
          score: 0.1,
          description: 'foo',
          options: ['foo', 'bar'],
        },
        BAR: {
          name: 'BAR',
          score: 1.0,
          description: 'bar',
        },
      },
    }
    this.plugin.cfg.main.add_headers = 'always'
    this.plugin.add_headers(this.connection, test_data)
    assert.deepEqual(
      this.connection.transaction.header.headers['x-rspamd-score'],
      ['1.1'],
    )
    assert.deepEqual(
      this.connection.transaction.header.headers['x-rspamd-bar'],
      ['+'],
    )
    assert.deepEqual(
      this.connection.transaction.header.headers['x-rspamd-report'],
      ['FOO(0.1) BAR(1)'],
    )
  })

  it('adds a header to a message with negative score', () => {
    const test_data = { score: -1 }
    this.plugin.cfg.main.add_headers = 'always'
    this.plugin.add_headers(this.connection, test_data)
    assert.deepEqual(
      this.connection.transaction.header.headers['x-rspamd-score'],
      ['-1'],
    )
    assert.deepEqual(
      this.connection.transaction.header.headers['x-rspamd-bar'],
      ['-'],
    )
  })
})

describe('wants_headers_added', () => {
  beforeEach(_set_up)

  it('wants no headers when add_headers=never', () => {
    this.plugin.cfg.main.add_headers = 'never'
    assert.equal(
      this.plugin.wants_headers_added({ action: 'add header' }),
      false,
    )
  })

  it('always wants no headers when add_headers=always', () => {
    this.plugin.cfg.main.add_headers = 'always'
    assert.equal(this.plugin.wants_headers_added({ action: 'beat it' }), true)
  })

  it('wants headers when rspamd response indicates, add_headers=sometimes', () => {
    this.plugin.cfg.main.add_headers = 'sometimes'
    assert.equal(
      this.plugin.wants_headers_added({ action: 'add header' }),
      true,
    )
    assert.equal(
      this.plugin.wants_headers_added({ action: 'brownlist' }),
      false,
    )
  })
})

describe('parse_response', () => {
  beforeEach(_set_up)

  it('returns undef on empty string', () => {
    assert.equal(this.plugin.parse_response('', this.connection), undefined)
  })

  it('returns undef on empty object', () => {
    assert.equal(this.plugin.parse_response('{}', this.connection), undefined)
  })
})

describe('should_check', () => {
  beforeEach(() => {
    this.plugin = makePlugin('rspamd', { register: false })
    this.plugin.register()
    this.connection = makeConnection()
    this.connection.init_transaction()

    // init defaults
    this.plugin.cfg.check.local_ip = false
    this.plugin.cfg.check.private_ip = false
    this.plugin.cfg.check.authenticated = false

    this.connection.remote.is_local = false
    this.connection.remote.is_private = false
    this.connection.notes.auth_user = undefined
  })

  it('checks authenticated', () => {
    this.connection.notes.auth_user = 'username'
    this.plugin.cfg.check.authenticated = true
    assert.equal(this.plugin.should_check(this.connection), true)
  })

  it('skips authenticated', () => {
    this.connection.notes.auth_user = 'username'
    this.plugin.cfg.check.authenticated = false
    assert.equal(this.plugin.should_check(this.connection), false)
  })

  it('skips relaying', () => {
    this.connection.relaying = true
    this.plugin.cfg.check.relay = false
    assert.equal(this.plugin.should_check(this.connection), false)
  })

  it('checks not relaying', () => {
    this.connection.relaying = false
    this.plugin.cfg.check.relay = false
    assert.equal(this.plugin.should_check(this.connection), true)
  })

  it('checks relaying when enabled', () => {
    this.connection.relaying = true
    this.plugin.cfg.check.relay = true
    assert.equal(this.plugin.should_check(this.connection), true)
  })

  it('checks local IP', () => {
    this.connection.remote.is_local = true
    this.plugin.cfg.check.local_ip = true
    assert.equal(this.plugin.should_check(this.connection), true)
  })

  it('skips local IP', () => {
    this.connection.remote.is_local = true
    this.plugin.cfg.check.local_ip = false
    assert.equal(this.plugin.should_check(this.connection), false)
  })

  it('checks private IP', () => {
    this.connection.remote.is_private = true
    this.plugin.cfg.check.private_ip = true
    assert.equal(this.plugin.should_check(this.connection), true)
  })

  it('skips private IP', () => {
    this.connection.remote.is_private = true
    this.plugin.cfg.check.private_ip = false
    assert.equal(this.plugin.should_check(this.connection), false)
  })

  it('checks public ip', () => {
    assert.equal(this.plugin.should_check(this.connection), true)
  })

  it('skip localhost if check.local_ip = false and check.private_ip = true', () => {
    this.connection.remote.is_local = true
    this.connection.remote.is_private = true
    this.plugin.cfg.check.local_ip = false
    this.plugin.cfg.check.private_ip = true
    assert.equal(this.plugin.should_check(this.connection), false)
  })

  it('checks localhost if check.local_ip = true and check.private_ip = false', () => {
    this.connection.remote.is_local = true
    this.connection.remote.is_private = true
    this.plugin.cfg.check.local_ip = true
    this.plugin.cfg.check.private_ip = false
    assert.equal(this.plugin.should_check(this.connection), true)
  })
})

describe.skip('data_post', () => {
  beforeEach(_set_up)

  it('streams a message to rspamd and gets response', (t, done) => {
    this.plugin.cfg.main.host = 'mail.example.com'
    this.plugin.cfg.main.timeout = 29000
    this.plugin.cfg.check.local_ip = true
    this.plugin.cfg.check.private_ip = true
    this.plugin.cfg.check.relay = true

    this.connection.remote.ip = '209.85.208.48'
    this.connection.hello.host = 'mail-ed1-f48.google.com'

    const specimen = fs.readFileSync('./test/fixtures/spam.eml', 'utf8')

    for (const line of specimen.split(/\r?\n/g)) {
      this.connection.transaction.add_data(`${line}\r\n`)
    }

    this.connection.transaction.end_data()
    this.connection.transaction.ensure_body()

    this.plugin.hook_data_post(() => {
      done()
    }, this.connection)
  })
})

// Regression for haraka/message-stream#22.
describe('rspamd request cleanup', () => {
  let server

  beforeEach((t, done) => {
    this.plugin = makePlugin('rspamd', { register: false })
    this.plugin.register()
    this.connection = makeConnection()
    this.connection.init_transaction()
    const txn = this.connection.transaction
    txn.mail_from = new Address('<m@example.com>')
    txn.rcpt_to = [new Address('<r@example.com>')]
    txn.uuid = 'TEST-UUID'
    txn.message_stream.add_line('Header: 1\r\n')
    txn.message_stream.add_line('\r\n')
    txn.message_stream.add_line('Body\r\n')
    txn.message_stream.add_line_end(done)
  })

  afterEach((t, done) => {
    if (server) server.close(done)
    else done()
  })

  it('unpipes message_stream when rspamd drops the request', (t, done) => {
    // Fake rspamd that accepts then immediately destroys the socket.
    server = http.createServer(() => {})
    server.on('connection', (s) => setImmediate(() => s.destroy()))
    server.listen(0, '127.0.0.1', () => {
      this.plugin.cfg.main.host = '127.0.0.1'
      this.plugin.cfg.main.port = server.address().port

      this.plugin.hook_data_post(() => {
        const dest = new PassThrough()
        dest.resume()
        assert.doesNotThrow(
          () => this.connection.transaction.message_stream.pipe(dest),
          'message_stream must be free for re-pipe after req error',
        )
        done()
      }, this.connection)
    })
  })

  it('unpipes message_stream on timeout', (t, done) => {
    // Server that accepts then hangs — forces the plugin timeout path.
    server = http.createServer(() => {
      /* never respond */
    })
    server.listen(0, '127.0.0.1', () => {
      this.plugin.cfg.main.host = '127.0.0.1'
      this.plugin.cfg.main.port = server.address().port
      this.plugin.cfg.main.timeout = 1 // 1s

      this.plugin.hook_data_post(() => {
        const dest = new PassThrough()
        dest.resume()
        assert.doesNotThrow(
          () => this.connection.transaction.message_stream.pipe(dest),
          'message_stream must be free for re-pipe after timeout',
        )
        done()
      }, this.connection)
    })
  })
})

// ─── Characterization tests ──────────────────────────────────────────────────
// These lock in current behavior of the uncovered exports prior to refactor.
// If any assertion changes, the refactor changed observable behavior — that
// should be intentional and reflected in the CHANGELOG.

describe('get_options', () => {
  beforeEach(_set_up)

  it('uses unix_socket when configured', () => {
    this.plugin.cfg.main.unix_socket = '/var/run/rspamd.sock'
    const opts = this.plugin.get_options(this.connection)
    assert.equal(opts.socketPath, '/var/run/rspamd.sock')
    assert.equal(opts.port, undefined)
    assert.equal(opts.host, undefined)
  })

  it('uses host/port when no unix_socket', () => {
    this.plugin.cfg.main.host = 'rspamd.example.com'
    this.plugin.cfg.main.port = 11334
    const opts = this.plugin.get_options(this.connection)
    assert.equal(opts.host, 'rspamd.example.com')
    assert.equal(opts.port, 11334)
    assert.equal(opts.socketPath, undefined)
  })

  it('sets request method and path', () => {
    const opts = this.plugin.get_options(this.connection)
    assert.equal(opts.method, 'POST')
    assert.equal(opts.path, '/checkv2')
  })

  it('supports custom request path', () => {
    this.plugin.cfg.main.path = '/checkv3'
    const opts = this.plugin.get_options(this.connection)
    assert.equal(opts.path, '/checkv3')
  })

  it('sets User header from auth_user', () => {
    this.connection.notes.auth_user = 'bob@example.com'
    const opts = this.plugin.get_options(this.connection)
    assert.equal(opts.headers.User, 'bob@example.com')
  })

  it('sets IP header from remote.ip', () => {
    this.connection.remote.ip = '203.0.113.5'
    const opts = this.plugin.get_options(this.connection)
    assert.equal(opts.headers.IP, '203.0.113.5')
  })

  it('prefers fcrdns Hostname over remote.host', () => {
    this.connection.remote.host = 'fallback.example.com'
    this.connection.results.add(
      { name: 'fcrdns' },
      { fcrdns: ['real.example.com'] },
    )
    const opts = this.plugin.get_options(this.connection)
    assert.equal(opts.headers.Hostname, 'real.example.com')
  })

  it('falls back to remote.host when no fcrdns result', () => {
    this.connection.remote.host = 'fallback.example.com'
    const opts = this.plugin.get_options(this.connection)
    assert.equal(opts.headers.Hostname, 'fallback.example.com')
  })

  it('sets Helo from hello.host', () => {
    this.connection.hello.host = 'helo.example.com'
    const opts = this.plugin.get_options(this.connection)
    assert.equal(opts.headers.Helo, 'helo.example.com')
  })

  it('SPF from transaction results wins over connection results', () => {
    this.connection.results.add({ name: 'spf' }, { result: 'NEUTRAL' })
    this.connection.transaction.results.add({ name: 'spf' }, { result: 'PASS' })
    const opts = this.plugin.get_options(this.connection)
    assert.deepEqual(opts.headers.SPF, { result: 'pass' })
  })

  it('falls back to connection SPF when transaction has none', () => {
    this.connection.results.add({ name: 'spf' }, { result: 'FAIL' })
    const opts = this.plugin.get_options(this.connection)
    assert.deepEqual(opts.headers.SPF, { result: 'fail' })
  })

  it('sets From from mail_from', () => {
    this.connection.transaction.mail_from = new Address('<sender@example.com>')
    const opts = this.plugin.get_options(this.connection)
    assert.equal(opts.headers.From, 'sender@example.com')
  })

  it('single rcpt gets Rcpt and Deliver-To', () => {
    this.connection.transaction.rcpt_to = [new Address('<one@example.com>')]
    const opts = this.plugin.get_options(this.connection)
    assert.deepEqual(opts.headers.Rcpt, ['one@example.com'])
    assert.equal(opts.headers['Deliver-To'], 'one@example.com')
  })

  it('multi rcpt gets Rcpt array only (no Deliver-To)', () => {
    this.connection.transaction.rcpt_to = [
      new Address('<one@example.com>'),
      new Address('<two@example.com>'),
    ]
    const opts = this.plugin.get_options(this.connection)
    assert.deepEqual(opts.headers.Rcpt, ['one@example.com', 'two@example.com'])
    assert.equal(opts.headers['Deliver-To'], undefined)
  })

  it('sets Queue-Id from transaction uuid', () => {
    this.connection.transaction.uuid = 'ABC-123'
    const opts = this.plugin.get_options(this.connection)
    assert.equal(opts.headers['Queue-Id'], 'ABC-123')
  })

  it('sets TLS headers when tls.enabled', () => {
    this.connection.tls.enabled = true
    this.connection.tls.cipher = {
      name: 'TLS_AES_256_GCM_SHA384',
      version: 'TLSv1.3',
    }
    const opts = this.plugin.get_options(this.connection)
    assert.equal(opts.headers['TLS-Cipher'], 'TLS_AES_256_GCM_SHA384')
    assert.equal(opts.headers['TLS-Version'], 'TLSv1.3')
  })

  it('sets https transport options when scheme=https', () => {
    this.plugin.cfg.main.scheme = 'https'
    this.plugin.cfg.main.host = 'rspamd.example.com'
    this.plugin.cfg.main.port = 443
    this.plugin.cfg.tls.servername = 'scan.example.com'
    this.plugin.cfg.tls.reject_unauthorized = false
    const opts = this.plugin.get_options(this.connection)
    assert.equal(opts.protocol, 'https:')
    assert.equal(opts.host, 'rspamd.example.com')
    assert.equal(opts.port, 443)
    assert.equal(opts.servername, 'scan.example.com')
    assert.equal(opts.rejectUnauthorized, false)
  })

  it('loads https cert options from files', () => {
    this.plugin.cfg.main.scheme = 'https'
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rspamd-test-'))
    const caFile = path.join(dir, 'ca.pem')
    const certFile = path.join(dir, 'cert.pem')
    const keyFile = path.join(dir, 'key.pem')
    try {
      fs.writeFileSync(caFile, 'ca')
      fs.writeFileSync(certFile, 'cert')
      fs.writeFileSync(keyFile, 'key')
      this.plugin.cfg.tls.ca_file = caFile
      this.plugin.cfg.tls.cert_file = certFile
      this.plugin.cfg.tls.key_file = keyFile

      const opts = this.plugin.get_options(this.connection)
      assert.equal(opts.ca.toString(), 'ca')
      assert.equal(opts.cert.toString(), 'cert')
      assert.equal(opts.key.toString(), 'key')
    } finally {
      fs.rmSync(dir, { recursive: true, force: true })
    }
  })

  it('sets rspamd settings controls', () => {
    this.plugin.cfg.request.settings_id = 'uribl'
    this.plugin.cfg.request.settings = '{"groups_enabled":["surbl"]}'
    this.plugin.cfg.request.flags = 'groups,milter'
    this.plugin.cfg.request.ext_urls = true
    this.plugin.cfg.request.pass_all = true

    const opts = this.plugin.get_options(this.connection)
    assert.equal(opts.headers['Settings-ID'], 'uribl')
    assert.equal(opts.headers.Settings, '{"groups_enabled":["surbl"]}')
    assert.equal(opts.headers.Pass, 'all')
    assert.equal(opts.headers.Flags, 'groups,milter,ext_urls')
  })

  it('sets basic auth header', () => {
    this.plugin.cfg.auth = {
      basic_user: 'u',
      basic_pass: 'p',
    }
    const opts = this.plugin.get_options(this.connection)
    assert.equal(opts.headers.Authorization, 'Basic dTpw')
  })

  it('sets header auth from env var', () => {
    process.env.RSPAMD_AUTH = 'Bearer abc123'
    try {
      this.plugin.cfg.auth = {
        header: 'Authorization',
        value_env: 'RSPAMD_AUTH',
      }
      const opts = this.plugin.get_options(this.connection)
      assert.equal(opts.headers.Authorization, 'Bearer abc123')
    } finally {
      delete process.env.RSPAMD_AUTH
    }
  })

  it('sets request_headers from config', () => {
    this.plugin.cfg.request_headers = {
      'MTA-Tag': 'outbound',
      'X-API-Key': 'sekret',
    }
    const opts = this.plugin.get_options(this.connection)
    assert.equal(opts.headers['MTA-Tag'], 'outbound')
    assert.equal(opts.headers['X-API-Key'], 'sekret')
  })
})

describe('get_request_client', () => {
  beforeEach(_set_up)

  it('returns http client for http options', () => {
    assert.equal(this.plugin.get_request_client({ protocol: 'http:' }), http)
  })

  it('returns https client for https options', () => {
    assert.equal(this.plugin.get_request_client({ protocol: 'https:' }), https)
  })

  it('returns http client for socketPath', () => {
    assert.equal(
      this.plugin.get_request_client({ socketPath: '/tmp/rspamd.sock' }),
      http,
    )
  })
})

describe('get_smtp_message', () => {
  beforeEach(_set_up)

  it('returns undefined when smtp_message disabled', () => {
    this.plugin.cfg.smtp_message.enabled = false
    assert.equal(
      this.plugin.get_smtp_message({
        data: { messages: { smtp_message: 'x' } },
      }),
      undefined,
    )
  })

  it('returns undefined when data.messages missing', () => {
    assert.equal(this.plugin.get_smtp_message({ data: {} }), undefined)
  })

  it('returns undefined when messages is not an object', () => {
    assert.equal(
      this.plugin.get_smtp_message({ data: { messages: 'string' } }),
      undefined,
    )
  })

  it('returns smtp_message when present', () => {
    assert.equal(
      this.plugin.get_smtp_message({
        data: { messages: { smtp_message: 'rejected by policy' } },
      }),
      'rejected by policy',
    )
  })
})

describe('do_rewrite', () => {
  beforeEach(_set_up)

  it('returns false when rewrite_subject disabled', () => {
    this.plugin.cfg.rewrite_subject.enabled = false
    assert.equal(
      this.plugin.do_rewrite(this.connection, { action: 'rewrite subject' }),
      false,
    )
  })

  it('returns false when action is not rewrite subject', () => {
    assert.equal(
      this.plugin.do_rewrite(this.connection, { action: 'add header' }),
      false,
    )
  })

  it('substitutes %s with old Subject', () => {
    this.connection.transaction.header.add('Subject', 'Hello there')
    this.plugin.do_rewrite(this.connection, {
      action: 'rewrite subject',
      subject: 'TAG: %s',
    })
    assert.equal(
      this.connection.transaction.header.get('Subject'),
      'TAG: Hello there',
    )
  })

  it('uses cfg.subject when data.subject absent', () => {
    this.connection.transaction.header.add('Subject', 'Hi')
    this.plugin.cfg.subject = '[X] %s'
    this.plugin.do_rewrite(this.connection, { action: 'rewrite subject' })
    assert.equal(this.connection.transaction.header.get('Subject'), '[X] Hi')
  })

  it('substitutes with empty string when no old Subject', () => {
    this.plugin.do_rewrite(this.connection, {
      action: 'rewrite subject',
      subject: 'TAG: %s',
    })
    assert.equal(this.connection.transaction.header.get('Subject'), 'TAG: ')
  })
})

describe('add_dkim_header', () => {
  beforeEach(_set_up)

  it('no-op when dkim disabled', () => {
    this.plugin.cfg.dkim.enabled = false
    this.plugin.add_dkim_header(this.connection, {
      'dkim-signature': 'v=1; a=rsa-sha256;...',
    })
    assert.equal(this.connection.transaction.header.get('DKIM-Signature'), '')
  })

  it('no-op when no signature in data', () => {
    this.plugin.cfg.dkim.enabled = true
    this.plugin.add_dkim_header(this.connection, {})
    assert.equal(this.connection.transaction.header.get('DKIM-Signature'), '')
  })

  it('adds header when enabled and signature present', () => {
    this.plugin.cfg.dkim.enabled = true
    this.plugin.add_dkim_header(this.connection, {
      'dkim-signature': 'v=1; a=rsa-sha256; d=example.com',
    })
    assert.equal(
      this.connection.transaction.header.get('DKIM-Signature'),
      'v=1; a=rsa-sha256; d=example.com',
    )
  })
})

describe('do_milter_headers', () => {
  beforeEach(_set_up)

  it('no-op when rmilter_headers disabled', () => {
    this.plugin.cfg.rmilter_headers.enabled = false
    this.plugin.do_milter_headers(this.connection, {
      milter: { add_headers: { 'X-Foo': 'bar' } },
    })
    assert.equal(this.connection.transaction.header.get('X-Foo'), '')
  })

  it('no-op when data.milter absent', () => {
    this.plugin.do_milter_headers(this.connection, {})
    // nothing to assert beyond no throw
    assert.ok(true)
  })

  it('removes headers listed in remove_headers', () => {
    this.connection.transaction.header.add('X-Drop', 'kill me')
    this.plugin.do_milter_headers(this.connection, {
      milter: { remove_headers: { 'X-Drop': 1 } },
    })
    assert.equal(this.connection.transaction.header.get('X-Drop'), '')
  })

  it('adds string header value', () => {
    this.plugin.do_milter_headers(this.connection, {
      milter: { add_headers: { 'X-Str': 'plain' } },
    })
    assert.equal(this.connection.transaction.header.get('X-Str'), 'plain')
  })

  it('adds {value: ...} object value', () => {
    this.plugin.do_milter_headers(this.connection, {
      milter: { add_headers: { 'X-Obj': { value: 'wrapped' } } },
    })
    assert.equal(this.connection.transaction.header.get('X-Obj'), 'wrapped')
  })

  it('adds each entry in an array of strings', () => {
    this.plugin.do_milter_headers(this.connection, {
      milter: { add_headers: { 'X-Arr': ['a', 'b'] } },
    })
    assert.deepEqual(this.connection.transaction.header.get_all('X-Arr'), [
      'a',
      'b',
    ])
  })

  it('adds each entry in an array of objects', () => {
    this.plugin.do_milter_headers(this.connection, {
      milter: {
        add_headers: { 'X-Arr': [{ value: 'a' }, { value: 'b' }] },
      },
    })
    assert.deepEqual(this.connection.transaction.header.get_all('X-Arr'), [
      'a',
      'b',
    ])
  })

  it('adds mixed array of strings and objects', () => {
    this.plugin.do_milter_headers(this.connection, {
      milter: { add_headers: { 'X-Arr': ['s', { value: 'o' }] } },
    })
    assert.deepEqual(this.connection.transaction.header.get_all('X-Arr'), [
      's',
      'o',
    ])
  })

  it('does not throw on circular-ref add_headers payload', () => {
    const add_headers = { 'X-OK': 'kept' }
    add_headers.self = add_headers // cycle in JSON.stringify
    assert.doesNotThrow(() => {
      this.plugin.do_milter_headers(this.connection, {
        milter: { add_headers },
      })
    })
  })
})

describe('wants_reject', () => {
  beforeEach(_set_up)

  it('returns false when action is not reject', () => {
    assert.equal(
      this.plugin.wants_reject(this.connection, { action: 'add header' }),
      false,
    )
  })

  it('authed + reject.authenticated=false → false', () => {
    this.connection.notes.auth_user = 'u'
    this.plugin.cfg.reject.authenticated = false
    assert.equal(
      this.plugin.wants_reject(this.connection, { action: 'reject' }),
      false,
    )
  })

  it('authed + reject.authenticated=true → true', () => {
    this.connection.notes.auth_user = 'u'
    this.plugin.cfg.reject.authenticated = true
    assert.equal(
      this.plugin.wants_reject(this.connection, { action: 'reject' }),
      true,
    )
  })

  it('anon + reject.spam=false → false', () => {
    this.plugin.cfg.reject.spam = false
    assert.equal(
      this.plugin.wants_reject(this.connection, { action: 'reject' }),
      false,
    )
  })

  it('anon + reject.spam=true → true', () => {
    this.plugin.cfg.reject.spam = true
    assert.equal(
      this.plugin.wants_reject(this.connection, { action: 'reject' }),
      true,
    )
  })
})

describe('get_clean', () => {
  beforeEach(_set_up)

  it('maps symbols name+score to clean.symbols dict', () => {
    const clean = this.plugin.get_clean(
      { symbols: { FOO: { name: 'FOO', score: 1.5 } } },
      this.connection,
    )
    assert.deepEqual(clean.symbols, { FOO: 1.5 })
  })

  it('copies scalar action/is_skipped/required_score/score keys', () => {
    const clean = this.plugin.get_clean(
      {
        action: 'no action',
        is_skipped: false,
        required_score: 5,
        score: 1.1,
      },
      this.connection,
    )
    assert.equal(clean.action, 'no action')
    assert.equal(clean.is_skipped, false)
    assert.equal(clean.required_score, 5)
    assert.equal(clean.score, 1.1)
  })

  it('collapses urls array to comma-separated string', () => {
    const clean = this.plugin.get_clean(
      { urls: ['http://a/', 'http://b/'] },
      this.connection,
    )
    assert.equal(clean.urls, 'http://a/,http://b/')
  })

  it('collapses emails array to comma-separated string', () => {
    const clean = this.plugin.get_clean(
      { emails: ['a@x', 'b@x'] },
      this.connection,
    )
    assert.equal(clean.emails, 'a@x,b@x')
  })

  it('collapses messages dict to "k : v" CSV', () => {
    // Fix for the dead-code bug where the join() result was discarded.
    const clean = this.plugin.get_clean(
      { messages: { smtp_message: 'rejected', other: 'note' } },
      this.connection,
    )
    assert.equal(clean.messages, 'smtp_message : rejected,other : note')
  })
})

describe('hook_data_post success paths', () => {
  let server

  beforeEach((t, done) => {
    this.plugin = makePlugin('rspamd', { register: false })
    this.plugin.register()
    this.connection = makeConnection()
    this.connection.init_transaction()
    const txn = this.connection.transaction
    txn.mail_from = new Address('<m@example.com>')
    txn.rcpt_to = [new Address('<r@example.com>')]
    txn.uuid = 'TEST-UUID'
    txn.message_stream.add_line('Header: 1\r\n')
    txn.message_stream.add_line('\r\n')
    txn.message_stream.add_line('Body\r\n')
    txn.message_stream.add_line_end(done)
  })

  afterEach((t, done) => {
    if (server) server.close(done)
    else done()
  })

  const startStub = (jsonOrRaw, cb) => {
    server = http.createServer((req, res) => {
      req.resume() // drain the request body
      req.on('end', () => {
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(
          typeof jsonOrRaw === 'string' ? jsonOrRaw : JSON.stringify(jsonOrRaw),
        )
      })
    })
    server.listen(0, '127.0.0.1', () => {
      this.plugin.cfg.main.host = '127.0.0.1'
      this.plugin.cfg.main.port = server.address().port
      cb()
    })
  }

  it('action=soft reject → DENYSOFT', (t, done) => {
    startStub({ action: 'soft reject', score: 5, required_score: 10 }, () => {
      this.plugin.hook_data_post((code) => {
        assert.equal(code, DENYSOFT)
        done()
      }, this.connection)
    })
  })

  it('action=reject → DENY (anon, reject.spam=true)', (t, done) => {
    startStub({ action: 'reject', score: 99, required_score: 10 }, () => {
      this.plugin.hook_data_post((code) => {
        assert.equal(code, DENY)
        done()
      }, this.connection)
    })
  })

  it('action=add header → CONT with headers added', (t, done) => {
    startStub(
      { action: 'add header', score: 5, required_score: 10, symbols: {} },
      () => {
        this.plugin.cfg.main.add_headers = 'sometimes'
        this.plugin.hook_data_post((code) => {
          assert.equal(code, undefined)
          assert.deepEqual(
            this.connection.transaction.header.headers['x-rspamd-score'],
            ['5'],
          )
          done()
        }, this.connection)
      },
    )
  })

  it('empty {} response → CONT', (t, done) => {
    startStub({}, () => {
      this.plugin.hook_data_post((code) => {
        assert.equal(code, undefined)
        done()
      }, this.connection)
    })
  })

  it('bad JSON + defer.error=true → DENYSOFT', (t, done) => {
    startStub('not json at all', () => {
      this.plugin.cfg.defer.error = true
      this.plugin.hook_data_post((code) => {
        assert.equal(code, DENYSOFT)
        done()
      }, this.connection)
    })
  })

  it('bad JSON + defer.error=false → CONT', (t, done) => {
    startStub('not json at all', () => {
      this.plugin.cfg.defer.error = false
      this.plugin.hook_data_post((code) => {
        assert.equal(code, undefined)
        done()
      }, this.connection)
    })
  })
})
