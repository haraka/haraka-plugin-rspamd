[![Build Status][ci-img]][ci-url]
[![Windows Build Status][ci-win-img]][ci-win-url]
[![Code Climate][clim-img]][clim-url]
[![Greenkeeper badge][gk-img]][gk-url]
[![NPM][npm-img]][npm-url]

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

- add\_headers

    Default: sometimes

    Possible values are:

        "always" - always add headers
        "never" - never add headers (unless provided by rspamd - see rmilter\_headers)
        "sometimes" - add headers when rspamd recommends `add header` action

    Format of these headers is governed by header.* settings

- reject.message

    Default: Detected as spam

    Message to send when rejecting mail due to Rspamd policy recommendation.

- reject.spam

    Default: true

    If set to false, ignore recommended *reject* action from Rspamd (except
    for authenticated users).

- reject.authenticated

    Default: false

    Reject messages from authenticated users if Rspamd recommends *reject*.

- check.authenticated

    Default: false

    If true, messages from authenticated users will be scanned by Rspamd.

- check.private\_ip

    Default: false

    If false, messages from private IPs will not be scanned by Rspamd.
    If true, messages from private IPs will be scanned by Rspamd.

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

- rmilter_headers.enabled

    Default: true

    If set to true, allow rspamd to add/remove headers to messages via [task:rmilter_set_reply()](https://rspamd.com/doc/lua/task.html#me7351).

- soft\_reject.enabled

    Default: true

    If set to true, allow rspamd to defer messages.

- soft\_reject.message

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

- timeout (in seconds)

    Default: 29 seconds

    How long to wait for a response from rspamd.


<!-- leave these buried at the bottom of the document -->
[ci-img]: https://travis-ci.org/haraka/haraka-plugin-rspamd.svg
[ci-url]: https://travis-ci.org/haraka/haraka-plugin-rspamd
[ci-win-img]: https://ci.appveyor.com/api/projects/status/xewfkqnt6yis1gen?svg=true
[ci-win-url]: https://ci.appveyor.com/project/msimerson/haraka-plugin-rspamd
[cov-img]: https://codecov.io/github/haraka/haraka-plugin-rspamd/coverage.svg
[cov-url]: https://codecov.io/github/haraka/haraka-plugin-rspamd
[clim-img]: https://codeclimate.com/github/haraka/haraka-plugin-rspamd/badges/gpa.svg
[clim-url]: https://codeclimate.com/github/haraka/haraka-plugin-rspamd
[gk-img]: https://badges.greenkeeper.io/haraka/haraka-plugin-rspamd.svg
[gk-url]: https://greenkeeper.io/
[npm-img]: https://nodei.co/npm/haraka-plugin-rspamd.png
[npm-url]: https://www.npmjs.com/package/haraka-plugin-rspamd
