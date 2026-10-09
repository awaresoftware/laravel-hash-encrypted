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

    expect(substr($packed, 0, 64))->toBe($crypto->blindIndex('john@example.com', 'email'))
        ->and(strlen($crypto->blindIndex('john@example.com', 'email')))->toBe(64);
});

test('the blind index is keyed so it cannot be reversed from the stored value', function () {
    $crypto = app(CryptoService::class);

    // A plain hash of a known address would be trivial to reverse with a word
    // list; the stored prefix must not match it.
    expect($crypto->blindIndex('john@example.com', 'email'))
        ->not->toBe(hash('sha256', 'john@example.com'));
});

test('the same input produces the same blind index prefix', function () {
    $crypto = app(CryptoService::class);

    $packed1 = $crypto->pack('john@example.com', 'email');
    $packed2 = $crypto->pack('  JOHN@EXAMPLE.COM  ', 'email');

    expect(substr($packed1, 0, 64))->toBe(substr($packed2, 0, 64));
});

test('different inputs produce different blind indexes', function () {
    $crypto = app(CryptoService::class);

    expect($crypto->blindIndex('john@example.com', 'email'))
        ->not->toBe($crypto->blindIndex('jane@example.com', 'email'));
});

test('packing the same value twice produces a different ciphertext', function () {
    $crypto = app(CryptoService::class);

    expect($crypto->pack('john@example.com', 'email'))->not->toBe($crypto->pack('john@example.com', 'email'));
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

    configureCrypto([
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

    configureCrypto(['crypto.encryption_key_id' => 5]);

    $packed = (new CryptoService)->pack('john@example.com', 'email');

    configureCrypto([
        'crypto.encryption_key_id' => 1,
        'crypto.previous_encryption_keys' => [],
    ]);

    expect(fn () => (new CryptoService)->unpack($packed, 'email'))
        ->toThrow(DecryptionFailed::class);
});

test('a value cannot be decrypted with the wrong key material', function () {
    $crypto = app(CryptoService::class);

    $packed = $crypto->pack('john@example.com', 'email');

    configureCrypto([
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
    configureCrypto(['crypto.cipher' => 'aes-256-cbc']);

    // The cipher is validated lazily, when a value is actually encrypted, so an
    // unauthenticated cipher must fail before any ciphertext is produced.
    expect(fn () => app(CryptoService::class)->pack('john@example.com', 'email'))
        ->toThrow(RuntimeException::class);
});

test('a blind index shorter than 32 characters is rejected', function () {
    configureCrypto(['crypto.blind_index_length' => 16]);

    // The service only reads the length when it splits a packed value, and the
    // query side rejects it up front, so both paths have to fail.
    expect(fn () => app(CryptoService::class)->unpack(str_repeat('a', 64), 'email'))
        ->toThrow(RuntimeException::class, 'must equal');
});

test('a malformed key is reported with an actionable message', function () {
    configureCrypto(['crypto.encryption_key' => 'base64:not-a-32-byte-key']);

    expect(fn () => new CryptoService)
        ->toThrow(RuntimeException::class, 'The [CRYPTO_ENCRYPTION_KEY] environment variable is missing or invalid.');
});

test('a missing blind index key is reported with an actionable message', function () {
    configureCrypto(['crypto.hash_key' => null]);

    expect(fn () => app(CryptoService::class)->blindIndex('john@example.com', 'email'))
        ->toThrow(RuntimeException::class, 'The [CRYPTO_HASH_KEY] environment variable is missing or invalid.');
});

test('a malformed previous key entry is reported', function () {
    configureCrypto(['crypto.previous_encryption_keys' => ['not-a-pair']]);

    expect(fn () => new CryptoService)
        ->toThrow(RuntimeException::class, 'must be a comma separated list of "keyId:key" pairs.');
});

test('an out of range encryption key id is rejected', function () {
    configureCrypto(['crypto.encryption_key_id' => 70000]);

    expect(fn () => new CryptoService)
        ->toThrow(RuntimeException::class, 'must be between 0 and 65535');
});

test('the field context is built from the configured template', function () {
    $crypto = app(CryptoService::class);

    expect($crypto->context('App\\Models\\User', 'users', 'email'))->toBe('users.email');

    configureCrypto(['crypto.aad' => '{model}:{column}']);

    expect($crypto->context('App\\Models\\User', 'users', 'email'))->toBe('App\\Models\\User:email');
});

/*
|--------------------------------------------------------------------------
| Security regressions
|--------------------------------------------------------------------------
*/

test('the same value gets unrelated blind indexes in different fields', function () {
    $crypto = app(CryptoService::class);

    // One shared HMAC key let a database dump join tables on the prefix.
    expect($crypto->blindIndex('john@example.com', 'users.email'))
        ->not->toBe($crypto->blindIndex('john@example.com', 'contacts.email'))
        ->and($crypto->blindIndex('john@example.com', 'users.email'))
        ->not->toBe($crypto->blindIndex('john@example.com', 'users.name'))
        ->and($crypto->blindIndex('john@example.com', 'users.email'))
        ->toBe($crypto->blindIndex(' JOHN@example.com ', 'users.email'));
})->group('security');

test('an additional authenticated data template without the column is rejected', function () {
    configureCrypto(['crypto.aad' => '{table}']);

    expect(fn () => app(CryptoService::class)->context('App\\Models\\User', 'users', 'email'))
        ->toThrow(RuntimeException::class, '{column}');
})->group('security');

test('a previous key cannot reuse the active key id', function () {
    // The previous key used to overwrite the active one silently.
    configureCrypto(['crypto.previous_encryption_keys' => ['1:base64:'.base64_encode(random_bytes(32))]]);

    expect(fn () => new CryptoService)
        ->toThrow(RuntimeException::class, 'key id [1]');
})->group('security');

test('previous key ids must be unique', function () {
    configureCrypto(['crypto.previous_encryption_keys' => [
        '2:base64:'.base64_encode(random_bytes(32)),
        '2:base64:'.base64_encode(random_bytes(32)),
    ]]);

    expect(fn () => new CryptoService)
        ->toThrow(RuntimeException::class, 'key id [2]');
})->group('security');

test('previous key ids must be integers between 0 and 65535', function (string $keyId) {
    configureCrypto(['crypto.previous_encryption_keys' => [$keyId.':base64:'.base64_encode(random_bytes(32))]]);

    expect(fn () => new CryptoService)->toThrow(RuntimeException::class);
})->with(['70000', '-1', '1.5', '0x10'])->group('security');

test('an active key is required even when previous keys are configured', function () {
    configureCrypto([
        'crypto.encryption_key' => null,
        'crypto.previous_encryption_keys' => ['2:base64:'.base64_encode(random_bytes(32))],
    ]);

    expect(fn () => new CryptoService)
        ->toThrow(RuntimeException::class, 'The [CRYPTO_ENCRYPTION_KEY] environment variable is missing or invalid.');
})->group('security');

test('a packed value whose prefix does not belong to its plaintext is rejected', function () {
    $crypto = app(CryptoService::class);

    // A row carrying the victim's blind index but the attacker's ciphertext
    // would otherwise be found by the victim's address and read as the attacker's.
    $victim = $crypto->pack('victim@example.com', 'users.email');
    $attacker = $crypto->pack('attacker@example.com', 'users.email');

    expect(fn () => $crypto->unpack(substr($victim, 0, 64).substr($attacker, 64), 'users.email'))
        ->toThrow(DecryptionFailed::class);
})->group('security');

test('plaintext and key material never reach an exception trace', function () {
    // Traces are logged and sent to error trackers.
    $previous = ini_set('zend.exception_ignore_args', '0');

    try {
        configureCrypto(['crypto.hash_key' => null]);

        $trace = '';

        try {
            app(CryptoService::class)->blindIndex('secret@example.com', 'users.email');
        } catch (RuntimeException $exception) {
            $trace = $exception->getTraceAsString();
        }

        configureCrypto(['crypto.encryption_key' => 'base64:'.base64_encode(str_repeat('k', 33))]);

        try {
            new CryptoService;
        } catch (RuntimeException $exception) {
            $trace .= $exception->getTraceAsString();
        }
    } finally {
        ini_set('zend.exception_ignore_args', (string) $previous);
    }

    expect($trace)->not->toBe('')
        ->and($trace)->not->toContain('secret@')
        ->and($trace)->not->toContain(substr(base64_encode(str_repeat('k', 33)), 0, 8));
})->group('security');

test('composed and decomposed unicode share one blind index', function () {
    $crypto = app(CryptoService::class);

    // Normalization used to be skipped silently without ext-intl.
    expect($crypto->blindIndex("Jose\u{0301}@example.com", 'users.email'))
        ->toBe($crypto->blindIndex("Jos\u{00E9}@example.com", 'users.email'));
})->group('security');

test('a blind index algorithm outside the allowlist is rejected', function () {
    // Md5 yields 32 hex characters, so the indexed prefix would include
    // random ciphertext bytes and the unique index would enforce nothing.
    configureCrypto(['crypto.hash_algorithm' => 'md5']);

    expect(fn () => app(CryptoService::class)->blindIndex('john@example.com', 'users.email'))
        ->toThrow(RuntimeException::class, 'not allowed');
})->group('security');

test('a blind index length that does not match the algorithm is rejected', function () {
    configureCrypto(['crypto.hash_algorithm' => 'sha512', 'crypto.blind_index_length' => 64]);

    expect(fn () => app(CryptoService::class)->blindIndex('john@example.com', 'users.email'))
        ->toThrow(RuntimeException::class, 'must equal');
})->group('security');

test('a longer algorithm works when the length matches it', function () {
    configureCrypto(['crypto.hash_algorithm' => 'sha512', 'crypto.blind_index_length' => 128]);

    $crypto = app(CryptoService::class);
    $packed = $crypto->pack('john@example.com', 'users.email');

    expect(strlen($crypto->blindIndex('john@example.com', 'users.email')))->toBe(128)
        ->and($crypto->unpack($packed, 'users.email'))->toBe('john@example.com');
})->group('security');

test('the blind index key must differ from the encryption key', function () {
    // One leaked key would otherwise unlock both rotation domains.
    configureCrypto(['crypto.hash_key' => config('crypto.encryption_key')]);

    expect(fn () => app(CryptoService::class)->blindIndex('john@example.com', 'users.email'))
        ->toThrow(RuntimeException::class, 'separate');
})->group('security');

test('the blind index key must differ from APP_KEY', function () {
    configureCrypto(['app.key' => config('crypto.hash_key')]);

    expect(fn () => app(CryptoService::class)->blindIndex('john@example.com', 'users.email'))
        ->toThrow(RuntimeException::class, 'separate');
})->group('security');

test('the encryption key must differ from APP_KEY', function () {
    configureCrypto(['app.key' => config('crypto.encryption_key')]);

    expect(fn () => new CryptoService)
        ->toThrow(RuntimeException::class, 'separate');
})->group('security');
