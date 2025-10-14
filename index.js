'use strict'

// node built-ins
const http = require('node:http')

// haraka libs
const DSN = require('haraka-dsn')

// mime libs
const libmime = require('libmime')

exports.register = function () {
  this.load_rspamd_ini()
}

exports.load_rspamd_ini = function () {
  const plugin = this

  plugin.cfg = plugin.config.get(
    'rspamd.ini',
    {
      booleans: [
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
      ],
    },
    () => {
      plugin.load_rspamd_ini()
    },
  )

  if (!this.cfg.reject.message) {
    this.cfg.reject.message = 'Detected as spam'
  }

  if (!this.cfg.soft_reject.message) {
    this.cfg.soft_reject.message = 'Deferred by policy'
  }

  if (!this.cfg.spambar) {
    this.cfg.spambar = { positive: '+', negative: '-', neutral: '/' }
  }

  if (!this.cfg.main.port) this.cfg.main.port = 11333
  if (!this.cfg.main.host) this.cfg.main.host = 'localhost'

  if (!this.cfg.main.add_headers) {
    if (this.cfg.main.always_add_headers === true) {
      this.cfg.main.add_headers = 'always'
    } else {
      this.cfg.main.add_headers = 'sometimes'
    }
  }

  if (!this.cfg.subject) {
    this.cfg.subject = '[SPAM] %s'
  }
}

exports.get_options = function (connection) {
  // https://rspamd.com/doc/architecture/protocol.html
  // https://github.com/vstakhov/rspamd/blob/master/rules/http_headers.lua
  const options = {
    headers: {},
    path: '/checkv2',
    method: 'POST',
  }

  if (this.cfg.main.unix_socket) {
    options.socketPath = this.cfg.main.unix_socket
  } else {
    options.port = this.cfg.main.port
    options.host = this.cfg.main.host
  }

  if (connection.notes.auth_user) {
    options.headers.User = connection.notes.auth_user
  }

  if (connection.remote.ip) options.headers.IP = connection.remote.ip

  const fcrdns = connection.results.get('fcrdns')
  if (fcrdns && fcrdns.fcrdns && fcrdns.fcrdns[0]) {
    options.headers.Hostname = fcrdns.fcrdns[0]
  } else {
    if (connection.remote.host) {
      options.headers.Hostname = connection.remote.host
    }
  }

  if (connection.hello.host) options.headers.Helo = connection.hello.host

  let spf = connection.transaction.results.get('spf')
  if (spf && spf.result) {
    options.headers.SPF = { result: spf.result.toLowerCase() }
  } else {
    spf = connection.results.get('spf')
    if (spf && spf.result) {
      options.headers.SPF = { result: spf.result.toLowerCase() }
    }
  }

  if (connection.transaction.mail_from) {
    let mfaddr = connection.transaction.mail_from.address().toString()

    try {
      // encode to utf-8 mime string that is pure ASCII
      mfaddr = libmime.encodeWord(mfaddr)
    } catch {
      // If cannot encode to utf-8 mime string then default to manual sanitanization
      const buffer = Buffer.from(mfaddr, 'utf8')
      mfaddr = buffer
        .toString('utf8')
        .replace(/\uFFFD/g, '') // replace wrong bytes' placeholder (�)
        // eslint-disable-next-line no-control-regex
        .replace(/[\x00-\x1F\x7F]/g, '') // remove control chars
        .trim()
    }

    if (mfaddr) {
      options.headers.From = mfaddr
    }
  }

  const rcpts = connection.transaction.rcpt_to
  if (rcpts) {
    options.headers.Rcpt = []
    for (const rcpt of rcpts) {
      options.headers.Rcpt.push(rcpt.address())
    }

    // for per-user options
    if (rcpts.length === 1) {
      options.headers['Deliver-To'] = options.headers.Rcpt[0]
    }
  }

  if (connection.transaction.uuid)
    options.headers['Queue-Id'] = connection.transaction.uuid

  if (connection.tls.enabled) {
    options.headers['TLS-Cipher'] = connection.tls.cipher.name
    options.headers['TLS-Version'] = connection.tls.cipher.version
  }

  return options
}

exports.get_smtp_message = function (r) {
  if (!this.cfg.smtp_message.enabled || !r.data.messages) return
  if (typeof r.data.messages !== 'object') return
  if (!r.data.messages.smtp_message) return

  return r.data.messages.smtp_message
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
  if (!data.milter) return

  if (data.milter.remove_headers) {
    for (const key of Object.keys(data.milter.remove_headers)) {
      connection.transaction.remove_header(key)
    }
  }

  if (data.milter.add_headers) {
    try {
      connection.logdebug(
        this,
        `milter.add_headers: ${JSON.stringify(data.milter.add_headers)}`,
      )
      for (const key of Object.keys(data.milter.add_headers)) {
        const header_values = data.milter.add_headers[key]
        if (!header_values) continue

        if (Object.prototype.toString.call(header_values) == '[object Array]') {
          header_values.forEach(function (header_value) {
            if (typeof header_value === 'object') {
              connection.transaction.add_header(key, header_value.value)
            } else {
              connection.transaction.add_header(key, header_value)
            }
          })
        } else if (typeof header_values === 'object') {
          connection.transaction.add_header(key, header_values.value)
        } else {
          connection.transaction.add_header(key, header_values)
        }
      }
    } catch (err) {
      connection.errorlog(this, `milter.addheaders error: ${err}`)
    }
  }
}

exports.hook_data_post = function (next, connection) {
  const plugin = this

  if (!connection.transaction) return next()
  if (!plugin.should_check(connection)) return next()

  let timer
  const timeout = plugin.cfg.main.timeout || plugin.timeout - 1

  let calledNext = false
  function nextOnce(code, msg) {
    clearTimeout(timer)
    if (calledNext) return
    calledNext = true
    if (!connection?.transaction) return
    next(code, msg)
  }

  timer = setTimeout(() => {
    if (!connection?.transaction) return
    connection.transaction.results.add(plugin, { err: 'timeout' })
    if (plugin.cfg.defer.timeout)
      return nextOnce(DENYSOFT, 'Rspamd scan timeout')
    nextOnce()
  }, timeout * 1000)

  const start = Date.now()

  const req = http.request(plugin.get_options(connection), (res) => {
    let rawData = ''

    res.on('data', (chunk) => {
      rawData += chunk
    })

    res.on('end', () => {
      if (!connection.transaction) return nextOnce() //client gone

      const r = plugin.parse_response(rawData, connection)
      if (!r || !r.data || !r.log) {
        if (plugin.cfg.defer.error)
          return nextOnce(DENYSOFT, 'Rspamd scan error')
        return nextOnce()
      }

      r.log.emit = true // spit out a log entry
      r.log.time = (Date.now() - start) / 1000

      connection.transaction.results.add(plugin, r.log)
      if (r.data.symbols)
        connection.transaction.results.add(plugin, { symbols: r.data.symbols })

      const smtp_message = plugin.get_smtp_message(r)

      plugin.do_rewrite(connection, r.data)

      if (plugin.cfg.soft_reject.enabled && r.data.action === 'soft reject') {
        nextOnce(
          DENYSOFT,
          DSN.sec_unauthorized(
            smtp_message || plugin.cfg.soft_reject.message,
            451,
          ),
        )
      } else if (plugin.wants_reject(connection, r.data)) {
        nextOnce(DENY, smtp_message || plugin.cfg.reject.message)
      } else {
        plugin.add_dkim_header(connection, r.data)
        plugin.do_milter_headers(connection, r.data)
        plugin.add_headers(connection, r.data)

        nextOnce()
      }
    })
  })

  req.on('error', (err) => {
    if (!connection?.transaction) return nextOnce() // client gone
    connection.transaction.results.add(plugin, { err: err.message })
    if (plugin.cfg.defer.error) return nextOnce(DENYSOFT, 'Rspamd scan error')
    nextOnce()
  })

  connection.transaction.message_stream.pipe(req)
  // pipe calls req.end() asynchronously
}

exports.should_check = function (connection) {
  let result = true // default

  if (this.cfg.check.authenticated == false && connection.notes.auth_user) {
    connection.transaction.results.add(this, { skip: 'authed' })
    result = false
  }

  if (this.cfg.check.relay == false && connection.relaying) {
    connection.transaction.results.add(this, { skip: 'relay' })
    result = false
  }

  if (this.cfg.check.local_ip == false && connection.remote.is_local) {
    connection.transaction.results.add(this, { skip: 'local_ip' })
    result = false
  }

  if (this.cfg.check.private_ip == false && connection.remote.is_private) {
    if (this.cfg.check.local_ip == true && connection.remote.is_local) {
      // local IPs are included in private IPs
    } else {
      connection.transaction.results.add(this, { skip: 'private_ip' })
      result = false
    }
  }

  return result
}

exports.wants_reject = function (connection, data) {
  if (data.action !== 'reject') return false

  if (connection.notes.auth_user) {
    if (this.cfg.reject.authenticated == false) return false
  } else {
    if (this.cfg.reject.spam == false) return false
  }

  return true
}

exports.wants_headers_added = function (rspamd_data) {
  if (this.cfg.main.add_headers === 'never') return false
  if (this.cfg.main.add_headers === 'always') return true

  // implicit add_headers=sometimes, based on rspamd response
  if (rspamd_data.action === 'add header') return true
  return false
}

exports.get_clean = function (data, connection) {
  const clean = { symbols: {} }

  if (data.symbols) {
    Object.keys(data.symbols).forEach((key) => {
      const a = data.symbols[key]
      // transform { name: KEY, score: VAL } -> { KEY: VAL }
      if (a.name && a.score !== undefined) {
        clean.symbols[a.name] = a.score
        return
      }
      // unhandled type
      connection.logerror(this, a)
    })
  }

  // objects that may exist
  const skip_keys = ['action', 'is_skipped', 'required_score', 'score']
  for (const key of skip_keys) {
    switch (typeof data[key]) {
      case 'boolean':
      case 'number':
      case 'string':
        clean[key] = data[key]
        break
      default:
        connection.loginfo(this, `skipping unhandled: ${typeof data[key]}`)
    }
  }

  // arrays which might be present
  const arrays = ['urls', 'emails', 'messages']
  for (const b of arrays) {
    // collapse to comma separated string, so values get logged
    if (!data[b]) continue

    if (data[b].length) {
      clean[b] = data[b].join(',')
      continue
    }

    if (typeof data[b] == 'object') {
      // 'messages' is probably a dictionary
      Object.keys(data[b])
        .map((k) => {
          return `${k} : ${data[b][k]}`
        })
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

  if (Object.keys(data).length === 0) return

  if (Object.keys(data).length === 1 && data.error) {
    connection.transaction.results.add(this, { err: data.error })
    return
  }

  return {
    data,
    log: this.get_clean(data, connection),
  }
}

exports.add_headers = function (connection, data) {
  const cfg = this.cfg

  if (!this.wants_headers_added(data)) return

  if (cfg.header && cfg.header.bar) {
    let spamBar = ''
    let spamBarScore = 1
    let spamBarChar = cfg.spambar.neutral || '/'
    if (data.score >= 1) {
      spamBarScore = Math.floor(data.score)
      spamBarChar = cfg.spambar.positive || '+'
    } else if (data.score <= -1) {
      spamBarScore = Math.floor(data.score * -1)
      spamBarChar = cfg.spambar.negative || '-'
    }
    for (let i = 0; i < spamBarScore; i++) {
      spamBar += spamBarChar
    }
    connection.transaction.remove_header(cfg.header.bar)
    connection.transaction.add_header(cfg.header.bar, spamBar)
  }

  if (cfg.header && cfg.header.report) {
    const prettySymbols = []
    for (const k in data.symbols) {
      if (data.symbols[k].score) {
        prettySymbols.push(`${data.symbols[k].name}(${data.symbols[k].score})`)
      }
    }
    connection.transaction.remove_header(cfg.header.report)
    connection.transaction.add_header(
      cfg.header.report,
      prettySymbols.join(' '),
    )
  }

  if (cfg.header && cfg.header.score) {
    connection.transaction.remove_header(cfg.header.score)
    connection.transaction.add_header(cfg.header.score, `${data.score}`)
  }
}
