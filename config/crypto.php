<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Encryption Key
    |--------------------------------------------------------------------------
    |
    | The AES-256-GCM key used to encrypt hash encrypted attributes. Generate a
    | key with the following command and store it in your environment file:
    |
    |   php -r "echo 'base64:' . base64_encode(random_bytes(32)) . PHP_EOL;"
    |
    | Every key is identified by a numeric key id. That id is embedded in each
    | encrypted value, which allows keys to be rotated without ever touching
    | the blind index that makes the column searchable. See the
    | "Previous Keys" section below for the rotation procedure.
    |
    */

    'encryption_key_id' => (int) env('CRYPTO_ENCRYPTION_KEY_ID', 1),

    'encryption_key' => env('CRYPTO_ENCRYPTION_KEY'),

    /*
    |--------------------------------------------------------------------------
    | Previous Keys
    |--------------------------------------------------------------------------
    |
    | A comma separated list of "keyId:key" pairs, e.g.
    |
    |   CRYPTO_PREVIOUS_KEYS=2:base64:AAA...,3:base64:BBB...
    |
    | To rotate the encryption key:
    |
    |   1. Move the current key to CRYPTO_PREVIOUS_KEYS (keeping its key id)
    |   2. Generate a new key and assign it a new id in CRYPTO_ENCRYPTION_KEY
    |   3. Run "php artisan crypto:re-encrypt" to re-encrypt stored values
    |   4. Once every row uses the new key, drop the old key from the list
    |
    */

    'previous_encryption_keys' => array_values(array_filter(array_map(
        'trim',
        explode(',', (string) env('CRYPTO_PREVIOUS_KEYS', '')),
    ))),

    /*
    |--------------------------------------------------------------------------
    | Blind Index Key
    |--------------------------------------------------------------------------
    |
    | The searchable prefix of a hash encrypted attribute is an HMAC of the
    | plaintext, keyed with this secret. A plain SHA-256 hash of an email
    | address is trivially reversible with a word list, so this key must be
    | treated as a secret, kept separate from the encryption key, and backed
    | up with the rest of your application secrets. Losing it makes every
    | stored value unrecoverable and unsearchable.
    |
    | Generate it with:
    |
    |   php -r "echo 'base64:' . base64_encode(random_bytes(32)) . PHP_EOL;"
    |
    */

    'hash_key' => env('CRYPTO_HASH_KEY'),

    /*
    |--------------------------------------------------------------------------
    | Cryptographic Parameters
    |--------------------------------------------------------------------------
    |
    | - "hash_algorithm" is the HMAC algorithm behind the blind index.
    | - "cipher" must be an authenticated cipher, GCM is required so that a
    |   tampered ciphertext is detected during decryption.
    | - "blind_index_length" is the number of leading characters reserved for
    |   the blind index inside a packed value. A hex encoded SHA-256 HMAC is
    |   64 characters long.
    | - "version" is the envelope version written into every packed value. It
    |   must be raised whenever the envelope layout changes, which makes old
    |   values fail loudly instead of silently.
    |
    */

    'hash_algorithm' => 'sha256',

    'cipher' => 'aes-256-gcm',

    'blind_index_length' => 64,

    'version' => 1,

    /*
    |--------------------------------------------------------------------------
    | Additional Authenticated Data
    |--------------------------------------------------------------------------
    |
    | The AAD is authenticated but not encrypted. It binds a ciphertext to the
    | column it belongs to, so an encrypted value cannot be moved to another
    | column and still decrypt. Both "{model}" and "{column}" placeholders
    | are supported. The default only uses the column name because renaming a
    | column or a model would otherwise make existing values unreadable; add
    | "{model}" if you prefer the stronger binding and accept the coupling.
    |
    */

    'aad' => '{column}',

    /*
    |--------------------------------------------------------------------------
    | Hash Encrypted Fields
    |--------------------------------------------------------------------------
    |
    | The list of attributes that are stored as a blind index followed by an
    | AES-256-GCM ciphertext, keyed by model class. Every listed attribute is
    | transparently encrypted on write, decrypted on read and searchable with
    | the whereEncrypted() scope.
    |
    | Configure it from your service provider rather than publishing this file:
    |
    |   Config::set('crypto.fields', [User::class => ['email', 'name']]);
    |
    */

    'fields' => [],

    /*
    |--------------------------------------------------------------------------
    | Blind Index Lookup Strategy
    |--------------------------------------------------------------------------
    |
    | How a blind index lookup is turned into SQL:
    |
    | - "expression" compares an index backed expression of the first N
    |   characters, created as a functional index. Supported by SQLite,
    |   PostgreSQL and MySQL 8.0.13+.
    | - "prefix_like" compares with "LIKE 'blind-index%'". It is the only
    |   option for MariaDB and for MySQL older than 8.0.13, which have no
    |   functional indexes, so a prefix index of the same width is created
    |   instead.
    |
    | Both strategies carry a UNIQUE constraint, and both are safe: the prefix
    | is exactly the blind index, because the packed value puts the blind index
    | first and the prefix index is created over precisely its length. A unique
    | prefix index over the whole blind index therefore still rejects duplicates.
    |
    | Set CRYPTO_BLIND_INDEX_STRATEGY to override the automatic detection.
    |
    */

    'blind_index_strategy' => env('CRYPTO_BLIND_INDEX_STRATEGY', 'auto'),

];
