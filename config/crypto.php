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
    | treated as a secret, kept separate from the encryption keys and APP_KEY
    | (both are enforced), and backed up with the rest of your application
    | secrets. A separate key is derived from it for every column. Losing it makes every
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
    | - "hash_algorithm" is the HMAC algorithm behind the blind index: one of
    |   sha256, sha384, sha512, sha3-256, sha3-384 or sha3-512.
    | - "cipher" must be an authenticated cipher, GCM is required so that a
    |   tampered ciphertext is detected during decryption.
    | - "blind_index_length" is the number of leading characters reserved for
    |   the blind index inside a packed value. It must equal the hex length of
    |   the HMAC: 64 for sha256 and sha3-256, 96 for the 384 bit algorithms,
    |   128 for the 512 bit ones.
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
    | Field Context
    |--------------------------------------------------------------------------
    |
    | Every hash encrypted column has a context built from this template. It
    | is the additional authenticated data of the ciphertext, and the domain
    | its blind index key is derived for. A packed value therefore cannot be
    | moved to another column or table and still decrypt, and the same value
    | stored in two columns produces unrelated blind indexes.
    |
    | The "{table}", "{column}" and "{model}" placeholders are supported, and
    | "{column}" is required. The default uses the table rather than the model
    | class, so renaming a class does not make existing values unreadable.
    | Renaming a table or a column does: re-encrypt the data when you do.
    |
    */

    'aad' => '{table}.{column}',

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
