'use strict';

// node built-ins
const http = require('http');

// haraka libs
const DSN = require('haraka-dsn');

exports.register = function () {
    this.load_rspamd_ini();
};

exports.load_rspamd_ini = function () {
    const plugin = this;

    plugin.cfg = plugin.config.get('rspamd.ini', {
        booleans: [
            '-check.authenticated',
            '+dkim.enabled',
            '-check.private_ip',
            '+reject.spam',
            '-reject.authenticated',
            '+rewrite_subject.enabled',
            '+rmilter_headers.enabled',
            '+soft_reject.enabled',
            '+smtp_message.enabled',
        ],
    }, function () {
        plugin.load_rspamd_ini();
    });

    if (!plugin.cfg.reject.message) {
        plugin.cfg.reject.message = 'Detected as spam';
    }

    if (!plugin.cfg.soft_reject.message) {
        plugin.cfg.soft_reject.message = 'Deferred by policy';
    }

    if (!plugin.cfg.spambar) {
        plugin.cfg.spambar = { positive: '+', negative: '-', neutral: '/' };
    }

    if (!plugin.cfg.main.port) plugin.cfg.main.port = 11333;
    if (!plugin.cfg.main.host) plugin.cfg.main.host = 'localhost';

    if (!plugin.cfg.main.add_headers) {
        if (plugin.cfg.main.always_add_headers === true) {
            plugin.cfg.main.add_headers = 'always';
        } else {
            plugin.cfg.main.add_headers = 'sometimes';
        }
    }

    if (!plugin.cfg.subject) {
        plugin.cfg.subject = "[SPAM] %s";
    }
};

exports.get_options = function (connection) {
    const plugin = this;

    // https://rspamd.com/doc/architecture/protocol.html
    // https://github.com/vstakhov/rspamd/blob/master/rules/http_headers.lua
    const options = {
        headers: {},
        port: plugin.cfg.main.port,
        host: plugin.cfg.main.host,
        path: '/checkv2',
        method: 'POST',
    };

    if (connection.notes.auth_user) {
        options.headers.User = connection.notes.auth_user;
    }

    if (connection.remote.ip) options.headers.IP = connection.remote.ip;

    const fcrdns = connection.results.get('fcrdns');
    if (fcrdns && fcrdns.fcrdns && fcrdns.fcrdns[0]) {
        options.headers.Hostname = fcrdns.fcrdns[0];
    }
    else {
        if (connection.remote.host) {
            options.headers.Hostname = connection.remote.host;
        }
    }

    if (connection.hello.host) options.headers.Helo = connection.hello.host;

    let spf = connection.transaction.results.get('spf');
    if (spf && spf.result) {
        options.headers.SPF = { result: spf.result.toLowerCase() };
    }
    else {
        spf = connection.results.get('spf');
        if (spf && spf.result) {
            options.headers.SPF = { result: spf.result.toLowerCase() };
        }
    }

    if (connection.transaction.mail_from) {
        const mfaddr = connection.transaction.mail_from.address().toString();
        if (mfaddr) {
            options.headers.From = mfaddr;
        }
    }

    const rcpts = connection.transaction.rcpt_to;
    if (rcpts) {
        options.headers.Rcpt = [];
        for (let i=0; i < rcpts.length; i++) {
            options.headers.Rcpt.push(rcpts[i].address());
        }

        // for per-user options
        if (rcpts.length === 1) {
            options.headers['Deliver-To'] = options.headers.Rcpt[0];
        }
    }

    if (connection.transaction.uuid)
        options.headers['Queue-Id'] = connection.transaction.uuid;

    return options;
};

exports.hook_data_post = function (next, connection) {
    if (!connection.transaction) return next();

    const plugin = this;
    const cfg = plugin.cfg;

    const authed = connection.notes.auth_user;
    if (authed && !cfg.check.authenticated) return next();
    if (!cfg.check.private_ip && connection.remote.is_private) {
        return next();
    }

    let timer;
    const timeout = plugin.cfg.main.timeout || plugin.timeout - 1;

    let calledNext=false;
    const callNext = function (code, msg) {
        clearTimeout(timer);
        if (calledNext) return;
        calledNext=true;
        next(code, msg);
    }

    timer = setTimeout(function () {
        if (!connection) return;
        if (!connection.transaction) return;
        connection.transaction.results.add(plugin, {err: 'timeout'});
        callNext();
    }, timeout * 1000);

    const options = plugin.get_options(connection);

    let req;
    let rawData = '';
    const start = Date.now();
    connection.transaction.message_stream.pipe(
        req = http.request(options, function (res) {
            res.on('data', function (chunk) { rawData += chunk; });
            res.on('end', function () {
                const r = plugin.parse_response(rawData, connection);
                if (!r) return callNext();
                if (!r.data) return callNext();
                if (!r.log) return callNext();

                r.log.emit = true; // spit out a log entry
                r.log.time = (Date.now() - start)/1000;

                if (!connection.transaction) return callNext();
                connection.transaction.results.add(plugin, r.log);

                let smtp_message;
                if (cfg.smtp_message.enabled && r.data.messages &&
                  typeof(r.data.messages) == 'object' && r.data.messages.smtp_message) {
                    smtp_message = r.data.messages.smtp_message;
                }

                function no_reject () {
                    if (cfg.dkim.enabled && r.data['dkim-signature']) {
                        connection.transaction.add_header('DKIM-Signature', r.data['dkim-signature']);
                    }
                    if (cfg.rmilter_headers.enabled && r.data.milter) {
                        if (r.data.milter.remove_headers) {
                            Object.keys(r.data.milter.remove_headers).forEach(function (key) {
                                connection.transaction.remove_header(key);
                            })
                        }
                        if (r.data.milter.add_headers) {
                            Object.keys(r.data.milter.add_headers).forEach(function (key) {
                                connection.transaction.add_header(key, r.data.milter.add_headers[key]);
                            })
                        }
                    }
                    if (plugin.wants_headers_added(r.data)) {
                        plugin.add_headers(connection, r.data);
                    }
                    return callNext();
                }

                if (cfg.rewrite_subject.enabled && r.data.action === 'rewrite subject') {
                    const rspamd_subject = r.data.subject || cfg.subject;
                    const old_subject = connection.transaction.header.get('Subject') || '';
                    const new_subject = rspamd_subject.replace('%s', old_subject);
                    connection.transaction.remove_header('Subject');
                    connection.transaction.add_header('Subject', new_subject);
                }

                if (cfg.soft_reject.enabled && r.data.action === 'soft reject') {
                    return callNext(DENYSOFT, DSN.sec_unauthorized(smtp_message || cfg.soft_reject.message, 451));
                }

                if (r.data.action !== 'reject') return no_reject();
                if (!authed && !cfg.reject.spam) return no_reject();
                if (authed && !cfg.reject.authenticated) return no_reject();

                return callNext(DENY, smtp_message || cfg.reject.message);
            });
        })
    );

    req.on('error', function (err) {
        if (!connection || !connection.transaction) return;
        connection.transaction.results.add(plugin, { err: err.message});
        return callNext();
    });
};

exports.wants_headers_added = function (rspamd_data) {
    const plugin = this;

    if (plugin.cfg.main.add_headers === 'never') return false;
    if (plugin.cfg.main.add_headers === 'always') return true;

    // implicit add_headers=sometimes, based on rspamd response
    if (rspamd_data.action === 'add header') return true;
    return false;
};

exports.parse_response = function (rawData, connection) {
    const plugin = this;

    let data;
    try {
        data = JSON.parse(rawData);
    }
    catch (err) {
        connection.transaction.results.add(plugin, {
            err: 'parse failure: ' + err.message
        });
        return;
    }

    if (Object.keys(data).length === 1 && data.error) {
        connection.transaction.results.add(plugin, {
            err: data.error
        });
        return;
    }

    // make cleaned data for logs
    const dataClean = {symbols: {}};
    Object.keys(data.symbols).forEach(function (key) {
        const a = data.symbols[key];
        // transform { name: KEY, score: VAL } -> { KEY: VAL }
        if (a.name && a.score !== undefined) {
            dataClean.symbols[ a.name ] = a.score;
        } else {
            // unhandled type
            connection.logerror(plugin, a);
        }
    });
    const wantKeys = ["action", "is_skipped", "required_score", "score"];
    wantKeys.forEach(function (key) {
        const a = data[key];
        switch (typeof a) {
            case 'boolean':
            case 'number':
            case 'string':
                dataClean[key] = a;
                break;
            default:
                connection.loginfo(plugin, "skipping unhandled: " + typeof a);
        }
    });

    // arrays which might be present
    ['urls', 'emails', 'messages'].forEach(function (b) {
        // collapse to comma separated string, so values get logged
        if (data[b]) {
            if (data[b].length) {
                dataClean[b] = data[b].join(',');
            } else if (typeof(data[b]) == 'object') {
                // 'messages' is probably a dictionary
                Object.keys(data[b]).map(function (k) {
                    return k + " : " + data[b][k];
                }).join(',');
            }
        }
    });

    return {
        'data' : data,
        'log' : dataClean,
    };
};

exports.add_headers = function (connection, data) {
    const plugin = this;
    const cfg = plugin.cfg;

    if (cfg.header && cfg.header.bar) {
        let spamBar = '';
        let spamBarScore = 1;
        let spamBarChar = cfg.spambar.neutral || '/';
        if (data.score >= 1) {
            spamBarScore = Math.floor(data.score);
            spamBarChar = cfg.spambar.positive || '+';
        }
        else if (data.score <= -1) {
            spamBarScore = Math.floor(data.score * -1);
            spamBarChar = cfg.spambar.negative || '-';
        }
        for (let i = 0; i < spamBarScore; i++) {
            spamBar += spamBarChar;
        }
        connection.transaction.remove_header(cfg.header.bar);
        connection.transaction.add_header(cfg.header.bar, spamBar);
    }

    if (cfg.header && cfg.header.report) {
        const prettySymbols = [];
        for (const k in data.symbols) {
            if (data.symbols[k].score) {
                prettySymbols.push(data.symbols[k].name +
                    '(' + data.symbols[k].score + ')');
            }
        }
        connection.transaction.remove_header(cfg.header.report);
        connection.transaction.add_header(cfg.header.report,
            prettySymbols.join(' '));
    }

    if (cfg.header && cfg.header.score) {
        connection.transaction.remove_header(cfg.header.score);
        connection.transaction.add_header(cfg.header.score, '' + data.score);
    }
};
