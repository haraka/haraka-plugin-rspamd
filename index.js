'use strict'

// node built-ins
const fs = require('node:fs')
const http = require('node:http')
const https = require('node:https')

// haraka libs
const DSN = require('haraka-dsn')

exports.register = function () {
  this.load_rspamd_ini()
}

const INI_BOOLEANS = [
  '-check.authenticated',
  '+dkim.enabled',
  '-check.private_ip',
  '-check.local_ip',
  '-check.relay',
  '+reject.spam',
  '-reject.authenticated',
  '+rewrite_subject.enabled',
  '+rmilter_headers.enabled',
  '+soft_reject.enabled',
  '+smtp_message.enabled',
  '-defer.error',
  '-defer.timeout',
  '-request.pass_all',
  '-request.body_block',
  '-request.groups',
  '-request.milter',
  '-request.no_log',
  '-request.profile',
  '-request.skip',
  '-request.skip_process',
  '-request.zstd',
  '-request.ext_urls',
  '-request.raw',
  '+tls.reject_unauthorized',
]

exports.load_rspamd_ini = function () {
  this.cfg = this.config.get('rspamd.ini', { booleans: INI_BOOLEANS }, () =>
    this.load_rspamd_ini(),
  )

  this.cfg.reject.message ??= 'Detected as spam'
  this.cfg.soft_reject.message ??= 'Deferred by policy'
  this.cfg.spambar ??= { positive: '+', negative: '-', neutral: '/' }
  this.cfg.main.host ??= 'localhost'
  this.cfg.main.port ??= 11333
  this.cfg.main.path ??= '/checkv2'
  this.cfg.main.scheme ??= 'http'
  this.cfg.subject ??= '[SPAM] %s'
  this.cfg.main.add_headers ??=
    this.cfg.main.always_add_headers === true ? 'always' : 'sometimes'
  this.cfg.tls ??= {}
  this.cfg.tls.reject_unauthorized ??= true
  this.cfg.request ??= {}
}

exports.get_options = function (connection) {
  // https://docs.rspamd.com/developers/protocol
  // https://github.com/rspamd/rspamd/blob/master/rules/headers_checks.lua
  const options = { headers: {}, path: this.cfg.main.path, method: 'POST' }
  set_transport(options, this.cfg)
  set_protocol(options, this.cfg)
  set_auth(options, connection)
  set_remote(options, connection)
  set_spf(options, connection)
  set_envelope(options, connection)
  set_tls(options, connection)
  set_upstream_auth(options, this.cfg)
  set_custom_headers(options, this.cfg)
  return options
}

function set_transport(options, cfg) {
  if (cfg.main.unix_socket) {
    options.socketPath = cfg.main.unix_socket
    return
  }

  options.host = cfg.main.host
  options.port = cfg.main.port
  if (get_scheme(cfg) === 'https') {
    options.protocol = 'https:'
    set_https_transport(options, cfg)
  } else {
    options.protocol = 'http:'
  }
}

function get_scheme(cfg) {
  const scheme = cfg.main.scheme?.toLowerCase()
  return scheme === 'https' ? 'https' : 'http'
}

function set_https_transport(options, cfg) {
  const tls = cfg.tls ?? {}
  options.rejectUnauthorized = tls.reject_unauthorized !== false
  if (tls.servername) options.servername = tls.servername
  if (tls.ca_file) options.ca = fs.readFileSync(tls.ca_file)
  if (tls.cert_file) options.cert = fs.readFileSync(tls.cert_file)
  if (tls.key_file) options.key = fs.readFileSync(tls.key_file)
}

function set_protocol(options, cfg) {
  const req = cfg.request ?? {}
  if (req.settings_id) options.headers['Settings-ID'] = req.settings_id
  if (req.settings) options.headers.Settings = req.settings
  if (req.pass_all) options.headers.Pass = 'all'
  if (req.raw) options.headers.Raw = 'yes'

  const flags = get_flags(req)
  if (flags.length) options.headers.Flags = flags.join(',')
  if (req.url_format) options.headers['URL-Format'] = req.url_format
}

function get_flags(req) {
  const flags = new Set(parse_flags(req.flags))
  const bool_flags = {
    body_block: req.body_block,
    ext_urls: req.ext_urls,
    groups: req.groups,
    milter: req.milter,
    no_log: req.no_log,
    profile: req.profile,
    skip: req.skip,
    skip_process: req.skip_process,
    zstd: req.zstd,
  }
  for (const [flag, enabled] of Object.entries(bool_flags)) {
    if (enabled) flags.add(flag)
  }
  return [...flags]
}

function parse_flags(raw) {
  if (Array.isArray(raw)) return raw.map((v) => `${v}`.trim()).filter((v) => v)
  if (typeof raw !== 'string') return []
  return raw
    .split(',')
    .map((v) => v.trim())
    .filter((v) => v)
}

function set_upstream_auth(options, cfg) {
  const auth = cfg.auth ?? {}
  if (auth.basic_user) {
    const auth_pass = auth.basic_pass ?? ''
    const token = Buffer.from(`${auth.basic_user}:${auth_pass}`).toString(
      'base64',
    )
    options.headers.Authorization = `Basic ${token}`
  }

  if (!auth.header) return
  const env_value = auth.value_env ? process.env[auth.value_env] : undefined
  const header_value = env_value ?? auth.value
  if (header_value) options.headers[auth.header] = header_value
}

function set_custom_headers(options, cfg) {
  const headers = cfg.request_headers
  if (!headers || typeof headers !== 'object') return

  for (const [key, value] of Object.entries(headers)) {
    if (!value) continue
    options.headers[key] = `${value}`
  }
}

function set_auth(options, connection) {
  if (connection.notes.auth_user)
    options.headers.User = connection.notes.auth_user
}

function set_remote(options, connection) {
  if (connection.remote.ip) options.headers.IP = connection.remote.ip
  const fcrdns = connection.results.get('fcrdns')
  const host = fcrdns?.fcrdns?.[0] ?? connection.remote.host
  if (host) options.headers.Hostname = host
  if (connection.hello.host) options.headers.Helo = connection.hello.host
}

function set_spf(options, connection) {
  const spf =
    connection.transaction.results.get('spf') ?? connection.results.get('spf')
  if (spf?.result) options.headers.SPF = { result: spf.result.toLowerCase() }
}

function set_envelope(options, connection) {
  const txn = connection.transaction
  const from = txn.mail_from?.address()?.toString()
  if (from) options.headers.From = from

  const rcpts = txn.rcpt_to
  if (rcpts?.length) {
    options.headers.Rcpt = rcpts.map((r) => r.address())
    // for per-user options
    if (rcpts.length === 1)
      options.headers['Deliver-To'] = options.headers.Rcpt[0]
  }

  if (txn.uuid) options.headers['Queue-Id'] = txn.uuid
}

function set_tls(options, connection) {
  if (!connection.tls.enabled) return
  options.headers['TLS-Cipher'] = connection.tls.cipher.name
  options.headers['TLS-Version'] = connection.tls.cipher.version
}

exports.get_smtp_message = function (r) {
  if (!this.cfg.smtp_message.enabled) return
  const messages = r?.data?.messages
  if (!messages || typeof messages !== 'object') return
  return messages.smtp_message
}

exports.do_rewrite = function (connection, data) {
  if (!this.cfg.rewrite_subject.enabled) return false
  if (data.action !== 'rewrite subject') return false

  const rspamd_subject = data.subject || this.cfg.subject
  const old_subject = connection.transaction.header.get('Subject') || ''
  const new_subject = rspamd_subject.replace('%s', old_subject)

  connection.transaction.remove_header('Subject')
  connection.transaction.add_header('Subject', new_subject)
}

exports.add_dkim_header = function (connection, data) {
  if (!this.cfg.dkim.enabled) return
  if (!data['dkim-signature']) return

  connection.transaction.add_header('DKIM-Signature', data['dkim-signature'])
}

exports.do_milter_headers = function (connection, data) {
  if (!this.cfg.rmilter_headers.enabled) return
  if (!data?.milter) return

  const { remove_headers, add_headers } = data.milter
  const txn = connection.transaction

  if (remove_headers) {
    for (const key of Object.keys(remove_headers)) txn.remove_header(key)
  }

  if (!add_headers) return

  try {
    connection.logdebug(
      this,
      `milter.add_headers: ${JSON.stringify(add_headers)}`,
    )
    for (const [key, value] of Object.entries(add_headers)) {
      if (value == null) continue
      if (Array.isArray(value)) {
        for (const v of value) add_milter_value(txn, key, v)
      } else {
        add_milter_value(txn, key, value)
      }
    }
  } catch (err) {
    connection.logerror(this, `milter.add_headers error: ${err}`)
  }
}

function add_milter_value(txn, key, value) {
  if (value && typeof value === 'object') {
    txn.add_header(key, value.value)
  } else {
    txn.add_header(key, value)
  }
}

exports.get_request_client = function (options) {
  if (options.socketPath) return http
  return options.protocol === 'https:' ? https : http
}

exports.hook_data_post = function (next, connection) {
  const plugin = this
  if (!connection.transaction) return next()
  if (!plugin.should_check(connection)) return next()

  const start = Date.now()
  const ctx = make_request_context(plugin, connection, next)

  ctx.timer = setTimeout(
    () => on_timeout(plugin, connection, ctx),
    (plugin.cfg.main.timeout || plugin.timeout - 1) * 1000,
  )

  const options = plugin.get_options(connection)
  const request_client = plugin.get_request_client(options)
  ctx.req = request_client.request(options, (res) => {
    let rawData = ''
    res.on('data', (chunk) => {
      rawData += chunk
    })
    res.on('end', () => on_response(plugin, connection, ctx, rawData, start))
  })

  ctx.req.on('error', (err) => on_request_error(plugin, connection, ctx, err))

  connection.transaction.message_stream.pipe(ctx.req)
  // pipe calls req.end() asynchronously
}

function make_request_context(plugin, connection, next) {
  const ctx = { req: null, timer: null, calledNext: false }
  ctx.nextOnce = (code, msg) => {
    // unpipe() before destroy() — see haraka/message-stream#22.
    connection?.transaction?.message_stream?.unpipe()
    if (ctx.req) ctx.req.destroy()
    clearTimeout(ctx.timer)
    if (ctx.calledNext) return
    ctx.calledNext = true
    if (!connection?.transaction) return
    next(code, msg)
  }
  return ctx
}

function on_timeout(plugin, connection, ctx) {
  if (!connection?.transaction) return
  connection.transaction.results.add(plugin, { err: 'timeout' })
  if (plugin.cfg.defer.timeout)
    return ctx.nextOnce(DENYSOFT, 'Rspamd scan timeout')
  ctx.nextOnce()
}

function on_request_error(plugin, connection, ctx, err) {
  if (!connection?.transaction) return ctx.nextOnce() // client gone
  connection.transaction.results.add(plugin, { err: err.message })
  if (plugin.cfg.defer.error) return ctx.nextOnce(DENYSOFT, 'Rspamd scan error')
  ctx.nextOnce()
}

function on_response(plugin, connection, ctx, rawData, start) {
  if (!connection.transaction) return ctx.nextOnce() // client gone

  const r = plugin.parse_response(rawData, connection)
  if (!r?.data || !r.log) {
    if (plugin.cfg.defer.error)
      return ctx.nextOnce(DENYSOFT, 'Rspamd scan error')
    return ctx.nextOnce()
  }

  r.log.emit = true // spit out a log entry
  r.log.time = (Date.now() - start) / 1000
  connection.transaction.results.add(plugin, r.log)
  if (r.data.symbols)
    connection.transaction.results.add(plugin, { symbols: r.data.symbols })

  plugin.do_rewrite(connection, r.data)

  const action = plugin.decide_action(connection, r)
  if (action) return ctx.nextOnce(...action)

  plugin.add_dkim_header(connection, r.data)
  plugin.do_milter_headers(connection, r.data)
  plugin.add_headers(connection, r.data)
  ctx.nextOnce()
}

exports.decide_action = function (connection, r) {
  const smtp_message = this.get_smtp_message(r)
  if (this.cfg.soft_reject.enabled && r.data.action === 'soft reject') {
    return [
      DENYSOFT,
      DSN.sec_unauthorized(smtp_message || this.cfg.soft_reject.message, 451),
    ]
  }
  if (this.wants_reject(connection, r.data)) {
    return [DENY, smtp_message || this.cfg.reject.message]
  }
  return null
}

exports.should_check = function (connection) {
  const check = this.cfg.check
  const remote = connection.remote
  const skip_rules = [
    ['authed', !check.authenticated && connection.notes.auth_user],
    ['relay', !check.relay && connection.relaying],
    ['local_ip', !check.local_ip && remote.is_local],
    // local IPs are a subset of private IPs — don't double-skip
    [
      'private_ip',
      !check.private_ip &&
        remote.is_private &&
        !(check.local_ip && remote.is_local),
    ],
  ]

  let result = true
  for (const [name, should_skip] of skip_rules) {
    if (!should_skip) continue
    connection.transaction.results.add(this, { skip: name })
    result = false
  }
  return result
}

exports.wants_reject = function (connection, data) {
  if (data.action !== 'reject') return false
  const flag = connection.notes.auth_user
    ? this.cfg.reject.authenticated
    : this.cfg.reject.spam
  return flag !== false
}

exports.wants_headers_added = function (rspamd_data) {
  if (this.cfg.main.add_headers === 'never') return false
  if (this.cfg.main.add_headers === 'always') return true

  // implicit add_headers=sometimes, based on rspamd response
  if (rspamd_data.action === 'add header') return true
  return false
}

const SCALAR_TYPES = new Set(['boolean', 'number', 'string'])
const SCALAR_KEYS = ['action', 'is_skipped', 'required_score', 'score']
const COLLECTION_KEYS = ['urls', 'emails', 'messages']

exports.get_clean = function (data, connection) {
  const clean = { symbols: {} }

  for (const [key, sym] of Object.entries(data.symbols ?? {})) {
    // transform { name: KEY, score: VAL } -> { KEY: VAL }
    if (sym?.name && sym.score !== undefined) {
      clean.symbols[sym.name] = sym.score
    } else {
      connection.logerror(this, sym ?? key)
    }
  }

  for (const key of SCALAR_KEYS) {
    if (data[key] === undefined) continue
    if (SCALAR_TYPES.has(typeof data[key])) {
      clean[key] = data[key]
    } else {
      connection.loginfo(this, `skipping unhandled: ${typeof data[key]}`)
    }
  }

  // collapse to comma-separated strings so values get logged
  for (const key of COLLECTION_KEYS) {
    const val = data[key]
    if (!val) continue
    if (Array.isArray(val)) {
      clean[key] = val.join(',')
    } else if (typeof val === 'object') {
      // dictionary form, e.g. messages: { smtp_message: '…' }
      clean[key] = Object.entries(val)
        .map(([k, v]) => `${k} : ${v}`)
        .join(',')
    }
  }

  return clean
}

exports.parse_response = function (rawData, connection) {
  if (!rawData) return

  let data
  try {
    data = JSON.parse(rawData)
  } catch (err) {
    connection.transaction.results.add(this, {
      err: `parse failure: ${err.message}`,
    })
    return
  }

  const keys = Object.keys(data)
  if (keys.length === 0) return
  if (keys.length === 1 && data.error) {
    connection.transaction.results.add(this, { err: data.error })
    return
  }

  return {
    data,
    log: this.get_clean(data, connection),
  }
}

exports.add_headers = function (connection, data) {
  if (!this.wants_headers_added(data)) return

  const { header, spambar } = this.cfg
  if (!header) return

  const txn = connection.transaction
  const values = {
    bar: make_spam_bar(data.score, spambar),
    report: format_symbols(data.symbols),
    score: `${data.score}`,
  }
  for (const [key, name] of Object.entries(header)) {
    if (!name || values[key] === undefined) continue
    replace_header(txn, name, values[key])
  }
}

function replace_header(txn, name, value) {
  txn.remove_header(name)
  txn.add_header(name, value)
}

function make_spam_bar(score, spambar) {
  if (score >= 1) return (spambar.positive || '+').repeat(Math.floor(score))
  if (score <= -1) return (spambar.negative || '-').repeat(Math.floor(-score))
  return spambar.neutral || '/'
}

function format_symbols(symbols) {
  const pretty = []
  for (const sym of Object.values(symbols ?? {})) {
    if (sym?.score) pretty.push(`${sym.name}(${sym.score})`)
  }
  return pretty.join(' ')
}
