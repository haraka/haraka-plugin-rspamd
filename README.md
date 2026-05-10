[![Build Status][ci-img]][ci-url]
[![Code Climate][clim-img]][clim-url]

# haraka-plugin-rspamd

This plugin facilitates scanning messages with Rspamd.

## Configuration

rspamd.ini

- host

  Default: localhost

  Host to connect to to query Rspamd.

- port

  Default: 11333

  Port Rspamd is listening on.

- unix_socket

  Path to a unix socket to connect to. If set, overrides host and port.

- scheme

  Default: http

  Transport for network connections (`http` or `https`). Ignored when
  `unix_socket` is set.

- path

  Default: /checkv2

  HTTP path for rspamd checks.

- add_headers

  Default: sometimes

  Possible values are:

        "always" - always add headers
        "never" - never add headers (unless provided by rspamd - see rmilter_headers)
        "sometimes" - add headers when rspamd recommends `add header` action

  Format of these headers is governed by header.\* settings

- tls.reject_unauthorized

  Default: true

  TLS certificate verification setting for HTTPS upstream requests.

- tls.servername

  Default: undefined

  Optional TLS SNI override when connecting via HTTPS.

- tls.ca_file / tls.cert_file / tls.key_file

  Default: undefined

  Optional PEM files for CA trust, client certificate, and client key when
  using HTTPS.

- auth.basic_user / auth.basic_pass

  Default: undefined

  Optional HTTP Basic Auth credentials for protected rspamd endpoints.

- auth.header / auth.value / auth.value_env

  Default: undefined

  Optional custom auth header. `auth.value_env` reads the header value from an
  environment variable.

- request.settings_id

  Default: undefined

  Sends `Settings-ID` header so rspamd can apply a named profile (for example,
  an URIBL-focused profile in `settings.conf`).

- request.settings

  Default: undefined

  Sends raw `Settings` header payload for per-request rspamd settings overrides.

- request.flags

  Default: undefined

  Comma-separated `Flags` header value for rspamd protocol options.

- request.body_block / request.ext_urls / request.groups / request.milter /
  request.no_log / request.profile / request.skip / request.skip_process /
  request.zstd

  Default: false

  Boolean helpers that append protocol flags to `Flags`.

- request.pass_all

  Default: false

  Sends `Pass: all` to force all rspamd filters for a request.

- request.raw

  Default: false

  Sends `Raw: yes` for non-MIME/raw body scanning.

- request.url_format

  Default: undefined

  Sets rspamd `URL-Format` header (for example, `extended`).

- request_headers.\*

  Default: undefined

  Additional headers to pass to rspamd (for example, `MTA-Tag`).

- reject.message

  Default: Detected as spam

  Message to send when rejecting mail due to Rspamd policy recommendation.

- reject.spam

  Default: true

  If set to false, ignore recommended _reject_ action from Rspamd (except
  for authenticated users).

- reject.authenticated

  Default: false

  Reject messages from authenticated users if Rspamd recommends _reject_.

- check.authenticated

  Default: false

  If true, messages from authenticated users will be scanned by Rspamd.

- check.relay

  Default: false

  If true, messages from relay clients will be scanned by Rspamd.

- check.private_ip

  Default: false

  If false, messages from private IPs will not be scanned by Rspamd.
  If true, messages from private IPs will be scanned by Rspamd.

- check.local_ip

  Default: false

  If false, messages from localhost will not be scanned by Rspamd.
  If true, messages from localhost will be scanned by Rspamd.

- dkim.enabled

  Default: true

  If set to true, allow rspamd to add DKIM signatures to messages.

- header.bar

  Default: undefined

  If set, add a visual spam level in a header with this name.

- header.report

  Default: undefined

  If set, add information about symbols matched & their scores in a header
  with this name.

- header.score

  Default: undefined

  If set, add the numeric spam score in a header with this name.

- rewrite_subject.enabled

  Default: true

  If set to true, "rewrite subject" action is honored.

- rmilter_headers.enabled

  Default: true

  If set to true, allow rspamd to add/remove headers to messages via [task:set_milter_reply()](https://rspamd.com/doc/lua/task.html#m70081).

- smtp_message.enabled

  Default: true

  If set to true, "smtp_message" provided by Rspamd is used in response for "reject" & "soft reject" actions.

- soft_reject.enabled

  Default: true

  If set to true, allow rspamd to defer messages.

- soft_reject.message

  Default: Deferred by policy

  Message to send to remote server on rspamd soft rejection.

- spambar.positive

  Default: +

  Used as character for visual spam-level where score is positive.

- spambar.negative

  Default: -

  Used as character for visual spam-level where score is negative.

- spambar.neutral

  Default: /

  Used as character for visual spam-level where score is zero.

- subject

  Default: [SPAM] %s

  Subject to use for `rewrite subject` action if Rspamd does not provide one.

- timeout (in seconds)

  Default: 29 seconds

  How long to wait for a response from rspamd.

<!-- leave these buried at the bottom of the document -->

[ci-img]: https://github.com/haraka/haraka-plugin-rspamd/actions/workflows/ci.yml/badge.svg
[ci-url]: https://github.com/haraka/haraka-plugin-rspamd/actions/workflows/ci.yml
[cov-img]: https://codecov.io/github/haraka/haraka-plugin-rspamd/coverage.svg
[cov-url]: https://codecov.io/github/haraka/haraka-plugin-rspamd
[clim-img]: https://codeclimate.com/github/haraka/haraka-plugin-rspamd/badges/gpa.svg
[clim-url]: https://codeclimate.com/github/haraka/haraka-plugin-rspamd
