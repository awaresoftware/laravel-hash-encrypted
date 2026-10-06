<?php

use Aware\HashEncrypted\CryptoService;
use Aware\HashEncrypted\Exceptions\DecryptionFailed;

/*
|--------------------------------------------------------------------------
| Packing
|--------------------------------------------------------------------------
*/

test('pack and unpack roundtrip', function () {
    $crypto = app(CryptoService::class);

    $packed = $crypto->pack('John@Example.COM', 'email');

    expect(strlen($packed))->toBeGreaterThan(64)
        ->and($crypto->unpack($packed, 'email'))->toBe('John@Example.COM');
});

test('the first characters of a packed value are the blind index', function () {
    $crypto = app(CryptoService::class);

    $packed = $crypto->pack('john@example.com', 'email');

    expect(substr($packed, 0, 64))->toBe($crypto->blindIndex('john@example.com'))
        ->and(strlen($crypto->blindIndex('john@example.com')))->toBe(64);
});

test('the blind index is keyed so it cannot be reversed from the stored value', function () {
    $crypto = app(CryptoService::class);

    // A plain hash of a known address would be trivial to reverse with a word
    // list; the stored prefix must not match it.
    expect($crypto->blindIndex('john@example.com'))
        ->not->toBe(hash('sha256', 'john@example.com'));
});

test('the same input produces the same blind index prefix', function () {
    $crypto = app(CryptoService::class);

    $packed1 = $crypto->pack('john@example.com');
    $packed2 = $crypto->pack('  JOHN@EXAMPLE.COM  ');

    expect(substr($packed1, 0, 64))->toBe(substr($packed2, 0, 64));
});

test('different inputs produce different blind indexes', function () {
    $crypto = app(CryptoService::class);

    expect($crypto->blindIndex('john@example.com'))
        ->not->toBe($crypto->blindIndex('jane@example.com'));
});

test('packing the same value twice produces a different ciphertext', function () {
    $crypto = app(CryptoService::class);

    expect($crypto->pack('john@example.com'))->not->toBe($crypto->pack('john@example.com'));
});

/*
|--------------------------------------------------------------------------
| Tamper resistance
|--------------------------------------------------------------------------
*/

test('a value cannot be decrypted under a different context', function () {
    $crypto = app(CryptoService::class);

    $packed = $crypto->pack('john@example.com', 'email');

    expect(fn () => $crypto->unpack($packed, 'name'))
        ->toThrow(DecryptionFailed::class);
});

test('a tampered ciphertext cannot be decrypted', function () {
    $crypto = app(CryptoService::class);

    $packed = $crypto->pack('john@example.com', 'email');

    // The bit is flipped inside the decoded envelope instead of in the base64
    // string, because the trailing bits of the last base64 group are discarded
    // and would not always change a byte.
    $envelope = base64_decode(substr($packed, 64), true);
    $envelope[20] = chr(ord($envelope[20]) ^ 0xFF);

    expect(fn () => $crypto->unpack(substr($packed, 0, 64).base64_encode($envelope), 'email'))
        ->toThrow(DecryptionFailed::class);
});

test('a tampered authentication tag cannot be decrypted', function () {
    $crypto = app(CryptoService::class);

    $packed = $crypto->pack('john@example.com', 'email');

    $envelope = base64_decode(substr($packed, 64), true);
    $envelope[strlen($envelope) - 1] = chr(ord($envelope[strlen($envelope) - 1]) ^ 0xFF);

    expect(fn () => $crypto->unpack(substr($packed, 0, 64).base64_encode($envelope), 'email'))
        ->toThrow(DecryptionFailed::class);
});

test('a malformed value cannot be decrypted', function () {
    $crypto = app(CryptoService::class);

    expect(fn () => $crypto->unpack(str_repeat('a', 64), 'email'))
        ->toThrow(DecryptionFailed::class);
});

/*
|--------------------------------------------------------------------------
| Key rotation
|--------------------------------------------------------------------------
*/

test('values encrypted with a previous key remain readable after a rotation', function () {
    $crypto = app(CryptoService::class);
    $previousKey = 'base64:'.base64_encode(random_bytes(32));

    config([
        'crypto.encryption_key_id' => 2,
        'crypto.previous_encryption_keys' => ['1:'.config('crypto.encryption_key')],
        'crypto.encryption_key' => $previousKey,
    ]);

    $rotated = new CryptoService;

    $packed = $crypto->pack('john@example.com', 'email');

    expect($crypto->keyIdOf($packed))->toBe(1)
        ->and($rotated->usesActiveKey($packed))->toBeFalse()
        ->and($rotated->unpack($packed, 'email'))->toBe('john@example.com');

    // Repacking keeps the blind index and switches the key id, which is exactly
    // what the crypto:re-encrypt command does for stored rows.
    $repacked = $rotated->repack($packed, 'email');

    expect(substr($repacked, 0, 64))->toBe(substr($packed, 0, 64))
        ->and($rotated->keyIdOf($repacked))->toBe(2)
        ->and($rotated->usesActiveKey($repacked))->toBeTrue()
        ->and($rotated->unpack($repacked, 'email'))->toBe('john@example.com');
});

test('a value encrypted with an unknown key cannot be decrypted', function () {
    $crypto = app(CryptoService::class);

    config(['crypto.encryption_key_id' => 5]);

    $packed = (new CryptoService)->pack('john@example.com', 'email');

    config([
        'crypto.encryption_key_id' => 1,
        'crypto.previous_encryption_keys' => [],
    ]);

    expect(fn () => (new CryptoService)->unpack($packed, 'email'))
        ->toThrow(DecryptionFailed::class);
});

test('a value cannot be decrypted with the wrong key material', function () {
    $crypto = app(CryptoService::class);

    $packed = $crypto->pack('john@example.com', 'email');

    config([
        'crypto.encryption_key' => 'base64:'.base64_encode(random_bytes(32)),
        'crypto.previous_encryption_keys' => [],
    ]);

    expect(fn () => (new CryptoService)->unpack($packed, 'email'))
        ->toThrow(DecryptionFailed::class);
});

/*
|--------------------------------------------------------------------------
| Change detection
|--------------------------------------------------------------------------
*/

test('isUnchanged recognises a packed value holding exactly the given plaintext', function () {
    $crypto = app(CryptoService::class);

    $packed = $crypto->pack('john@example.com', 'email');

    expect($crypto->isUnchanged($packed, 'john@example.com', 'email'))->toBeTrue()
        ->and($crypto->isUnchanged($packed, 'jane@example.com', 'email'))->toBeFalse();
});

test('isUnchanged returns false for a value that cannot be decrypted', function () {
    $crypto = app(CryptoService::class);

    expect($crypto->isUnchanged(str_repeat('a', 64), 'john@example.com', 'email'))->toBeFalse();
});

/*
|--------------------------------------------------------------------------
| Envelope layout
|--------------------------------------------------------------------------
*/

test('the envelope version is validated', function () {
    $crypto = app(CryptoService::class);

    $packed = $crypto->pack('john@example.com', 'email');
    $envelope = base64_decode(substr($packed, 64), true);

    // Rewrite the version byte to an unsupported value.
    $envelope[0] = chr(99);

    expect(fn () => $crypto->unpack(substr($packed, 0, 64).base64_encode($envelope), 'email'))
        ->toThrow(DecryptionFailed::class, 'The value uses the unsupported envelope version [99].');
});

test('a non authenticated cipher is rejected', function () {
    config(['crypto.cipher' => 'aes-256-cbc']);

    // The cipher is validated lazily, when a value is actually encrypted, so an
    // unauthenticated cipher must fail before any ciphertext is produced.
    expect(fn () => app(CryptoService::class)->pack('john@example.com', 'email'))
        ->toThrow(RuntimeException::class);
});

test('a blind index shorter than 32 characters is rejected', function () {
    config(['crypto.blind_index_length' => 16]);

    // The service only reads the length when it splits a packed value, and the
    // query side rejects it up front, so both paths have to fail.
    expect(fn () => app(CryptoService::class)->unpack(str_repeat('a', 64), 'email'))
        ->toThrow(RuntimeException::class);
});

test('a malformed key is reported with an actionable message', function () {
    config(['crypto.encryption_key' => 'base64:not-a-32-byte-key']);

    expect(fn () => new CryptoService)
        ->toThrow(RuntimeException::class, 'The [CRYPTO_ENCRYPTION_KEY] environment variable is missing or invalid.');
});

test('a missing blind index key is reported with an actionable message', function () {
    config(['crypto.hash_key' => null]);

    expect(fn () => app(CryptoService::class)->blindIndex('john@example.com'))
        ->toThrow(RuntimeException::class, 'The [CRYPTO_HASH_KEY] environment variable is missing or invalid.');
});

test('a malformed previous key entry is reported', function () {
    config(['crypto.previous_encryption_keys' => ['not-a-pair']]);

    expect(fn () => new CryptoService)
        ->toThrow(RuntimeException::class, 'must be a comma separated list of "keyId:key" pairs.');
});

test('an out of range encryption key id is rejected', function () {
    config(['crypto.encryption_key_id' => 70000]);

    expect(fn () => new CryptoService)
        ->toThrow(RuntimeException::class, 'must be between 0 and 65535');
});

test('the additional authenticated data is built from the configured template', function () {
    $crypto = app(CryptoService::class);

    expect($crypto->context('App\\Models\\User', 'email'))->toBe('email');

    config(['crypto.aad' => '{model}:{column}']);

    expect($crypto->context('App\\Models\\User', 'email'))->toBe('App\\Models\\User:email');
});
