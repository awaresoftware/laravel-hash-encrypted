# Changelog

All notable changes to `aware/hash-encrypted` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet.

## [0.1.0] — Unreleased

Initial release, extracted from a working application implementation.

### Added

- `CryptoService`: packs a plaintext value into a searchable, encrypted string
  — a fixed width HMAC blind index followed by a base64 encoded AES-256-GCM
  envelope carrying a version byte, a key id, a nonce and an authentication tag.
- `Casts\Encrypted` and `Concerns\HasHashEncryptedFields`: transparent
  encryption on write, decryption on read, and `whereEncrypted()` /
  `whereEncryptedIn()` lookup scopes.
- `Database\BlindIndex`: driver aware lookup expressions and index DDL, shared
  by the query scopes and the migration helper so the two cannot drift apart.
- `Database\CreatesBlindIndexes`: migration trait that creates the lookup
  indexes, including the MariaDB and pre-8.0.13 MySQL prefix index variant.
- `Rules\UniqueBlindIndex` and the `unique_encrypted` string rule: index backed
  uniqueness checks against encrypted columns.
- `Auth\HashEncryptedUserProvider`: a user provider driver that resolves
  credentials through blind indexes, so `Auth::attempt()`, password resets and
  password confirmations keep working against encrypted columns.
- `Console\ReEncryptCommand` (`crypto:re-encrypt`): key rotation with
  `--model`, `--column`, `--chunk`, `--force` and `--dry-run`.
- Driver strategy auto-detection, overridable through
  `CRYPTO_BLIND_INDEX_STRATEGY`.
- Publishable configuration under the `hash-encrypted-config` tag.

### Security notes

- The blind index is an HMAC under `CRYPTO_HASH_KEY`, not a bare hash, so a
  database dump cannot be reversed with a word list.
- `DecryptionFailed` never reports which step failed or what the value was.
- The ciphertext is bound to its column through additional authenticated data.
- The package config is merged **recursively**, so an application that
  published `config/crypto.php` keeps receiving new default keys on upgrade
  instead of silently losing them to a shallow `array_merge`.

### Known limitations

- Lookups are exact match only. Partial, prefix and fuzzy search are impossible
  from a single blind index and are not implemented.
- Ordering by an encrypted column sorts by blind index, which is effectively
  random.
- `CRYPTO_HASH_KEY` rotation is not a routine operation: it invalidates every
  blind index, so the table has to be re-encrypted and re-indexed.

[Unreleased]: https://github.com/aware/hash-encrypted/compare/v0.1.0...HEAD