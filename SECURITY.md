# Security Policy

`awaresoftware/laravel-hash-encrypted` protects personal data at rest, so a weakness in it can
expose every value an application stores with it. Reports are welcome and are
handled privately until a fix is released.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

Until 1.0, only the latest minor release receives security fixes. The package
supports Laravel 12 and 13 on PHP 8.3 or later.

## Reporting a vulnerability

**Do not open a public issue, pull request or discussion.**

Report it privately through GitHub:
[Report a vulnerability](https://github.com/awaresoftware/laravel-hash-encrypted/security/advisories/new)
(the **Security** tab of this repository, then **Report a vulnerability**).

Please include:

- the affected version, Laravel version, PHP version and database driver
- the configuration involved (`config/crypto.php` values, **never** your keys)
- what an attacker needs: database read or write access, an application
  account, or nothing at all
- a proof of concept, ideally a failing Pest test against this repository's
  test suite

## What to expect

- An acknowledgement within 5 business days.
- An assessment and a planned fix date within 14 days.
- A fix released as a patch version with a GitHub security advisory and a CVE
  where one applies. Reporters are credited unless they prefer otherwise.

Please allow 90 days, or until a fix is released if that is sooner, before
disclosing publicly.

## Scope

In scope: anything in this package that weakens what the
[threat model](README.md#threat-model) promises, for example:

- recovering plaintext, or a blind index key, from stored values
- linking values across columns or tables
- moving or forging a stored value so that it decrypts or matches a lookup
- bypassing uniqueness checks, or authenticating as another user, through the
  user provider
- plaintext or key material leaking into logs, exceptions or queries

Out of scope:

- the limits the threat model documents: equality within a column, ciphertext
  length, and copying a value between rows by someone with database write
  access
- leaked or weak keys, or keys stored in version control
- vulnerabilities in Laravel, PHP, OpenSSL or the database server; report those
  to their maintainers
