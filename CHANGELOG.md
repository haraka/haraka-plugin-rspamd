# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/).

### Unreleased

### [1.4.1] - 2025-10-20

- convert mfaddr to utf8 mime string, #45

### [1.4.0] - 2025-10-10

- sanitize helo host & mfrom email address (#43)
  - Sanitize helo host, allow only ASCII, utf8 encode to punycode
  - User email addr: sanitize, encode to utf8 mime if possible
- deps: bump versions to latest

### [1.3.3] - 2025-06-02

- fix: strip invalid bytes from MAIL FROM address (#40)

### [1.3.2] - 2025-01-26

- prefix node built-in modules with node:
- doc: mv Changes CHANGELOG.md
- doc(CONTRIBUTORS): added
- populate [files] in package.json.
- style: code formatting with prettier
- dep(eslint): upgrade to v9

### [1.3.1] - 2023-03-02

- fix for loop returns (#35)

### [1.3.0] - 2023-02-23

- add: defer options, similar to spamassassin.js #32
- es6: replace Object.keys().forEach with for...of
- fix: wrap milter header adds in try/catch, fixes #28

### [1.2.0] - 2022-10-14

- Make milter header handling compatible with rspamd 3.3 (#30)

### [1.1.8] - 2022-06-06

- doc(README): update CI badge URLs

### 1.1.7 - 2022-06-05

- ci: replace travis & appveyor with GitHub actions
- test: replace nodeunit with mocha
- test: update header checks against lower cased header names

### 1.1.6 - 2020-02-29

- Allow connecting to rspamd via unix sockets

### 1.1.5 - 2019-04-01

- store symbols in results (for other plugins to inspect)

### 1.1.4 - 2019-01-28

- fixed "TypeError: value.replace is not a function"

### 1.1.3 - 2018-12-19

- add check.relay option

### 1.1.2 - 2018-11-03

- add check.local_ip config option

### 1.1.1 - 2018-05-10

- pass TLS-Cipher and TLS-Version headers to rspamd (fixes #4)
- code smell: return cleanups
- es6: use arrow functions
- refactored hook_data_post, addressing excessive cognitive complexity

### 1.1.0 - 2018-01-12

- use /checkv2 endpoint (requires rspamd 1.6+)
- support setting SMTP message from rspamd
- support 'rewrite subject' action

### 1.0.0 - 2017-09-11

- initial release

[1.1.8]: https://github.com/haraka/haraka-plugin-rspamd/releases/tag/1.1.8
[1.1.9]: https://github.com/haraka/haraka-plugin-rspamd/releases/tag/1.1.9
[1.2.0]: https://github.com/haraka/haraka-plugin-rspamd/releases/tag/v1.2.0
[1.3.0]: https://github.com/haraka/haraka-plugin-rspamd/releases/tag/v1.3.0
[1.3.1]: https://github.com/haraka/haraka-plugin-rspamd/releases/tag/v1.3.1
[1.3.2]: https://github.com/haraka/haraka-plugin-rspamd/releases/tag/v1.3.2
[1.1.6]: https://github.com/haraka/haraka-plugin-rspamd/releases/tag/v1.1.6
[1.3.3]: https://github.com/haraka/haraka-plugin-rspamd/releases/tag/v1.3.3
[1.3.4]: https://github.com/haraka/haraka-plugin-rspamd/releases/tag/v1.3.4
[1.4.1]: https://github.com/haraka/haraka-plugin-rspamd/releases/tag/v1.4.1
[1.4.0]: https://github.com/haraka/haraka-plugin-rspamd/releases/tag/v1.4.0
