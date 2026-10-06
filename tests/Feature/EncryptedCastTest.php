<?php

use Aware\HashEncrypted\Casts\Encrypted;
use Aware\HashEncrypted\CryptoService;
use Aware\HashEncrypted\Exceptions\DecryptionFailed;
use Illuminate\Database\Eloquent\Casts\Attribute;
use Illuminate\Support\Facades\DB;
use Tests\HashEncrypted\Fixtures\TestUser;

/*
|--------------------------------------------------------------------------
| Transparent encryption
|--------------------------------------------------------------------------
*/

test('the fields declared in the configuration are reported by the trait', function () {
    $user = new TestUser;

    expect($user->hashEncryptedFields())->toBe(['email', 'name'])
        ->and($user->hasHashEncryptedField('email'))->toBeTrue()
        ->and($user->hasHashEncryptedField('password'))->toBeFalse();
});

test('the trait contributes the encrypted cast for every configured field', function () {
    $casts = (fn () => $this->hashEncryptedCasts())->call(new TestUser);

    expect($casts)->toBe([
        'email' => Encrypted::class,
        'name' => Encrypted::class,
    ]);
});

test('encrypted attributes are decrypted when read', function () {
    $user = TestUser::create([
        'name' => 'John Doe',
        'email' => 'john@example.com',
        'password' => 'password',
    ]);

    expect($user->fresh())
        ->name->toBe('John Doe')
        ->email->toBe('john@example.com');
});

test('the plaintext is not stored in the database', function () {
    TestUser::create([
        'name' => 'John Doe',
        'email' => 'john@example.com',
        'password' => 'password',
    ]);

    $row = (array) DB::table('test_users')->first();

    expect($row['email'])->toStartWith(app(CryptoService::class)->blindIndex('john@example.com'))
        ->and($row['email'])->not->toContain('john@example.com')
        ->and($row['name'])->not->toContain('John Doe');
});

test('an unchanged attribute is not rewritten on save', function () {
    $user = TestUser::create([
        'name' => 'John Doe',
        'email' => 'john@example.com',
        'password' => 'password',
    ]);

    $before = $user->getRawOriginal('email');

    $user->name = 'John Doe';
    $user->email = 'john@example.com';
    $user->save();

    expect($user->isDirty('email'))->toBeFalse()
        ->and($user->fresh()->getRawOriginal('email'))->toBe($before);
});

test('a changed attribute is encrypted again and reported as dirty', function () {
    $user = TestUser::create([
        'name' => 'John Doe',
        'email' => 'john@example.com',
        'password' => 'password',
    ]);

    $before = $user->getRawOriginal('email');

    $user->email = 'john.doe@example.com';

    expect($user->isDirty('email'))->toBeTrue();

    $user->save();

    expect($user->fresh()->getRawOriginal('email'))->not->toBe($before)
        ->and($user->fresh()->email)->toBe('john.doe@example.com');
});

test('only a case difference still rewrites the ciphertext', function () {
    $user = TestUser::create([
        'name' => 'John Doe',
        'email' => 'john@example.com',
        'password' => 'password',
    ]);

    $before = $user->getRawOriginal('email');

    $user->email = 'John@Example.com';
    $user->save();

    // Normalization is only used for the blind index, so the stored plaintext
    // keeps the casing the caller supplied.
    expect($user->fresh()->getRawOriginal('email'))->not->toBe($before)
        ->and($user->fresh()->email)->toBe('John@Example.com');
});

/*
|--------------------------------------------------------------------------
| Value handling
|--------------------------------------------------------------------------
*/

test('a null value is stored and read as null', function () {
    $user = new TestUser;

    expect($user->email)->toBeNull();
});

test('a non string value is rejected with an actionable message', function () {
    $user = new TestUser;

    expect(fn () => $user->email = ['not', 'a', 'string'])
        ->toThrow(InvalidArgumentException::class, 'must be a string');
});

test('a tampered stored value fails loudly on read', function () {
    $user = TestUser::create([
        'name' => 'John Doe',
        'email' => 'john@example.com',
        'password' => 'password',
    ]);

    $packed = $user->getRawOriginal('email');

    // The blind index still matches, so only the authentication tag can catch
    // this: the value has to fail closed rather than silently return garbage.
    $envelope = base64_decode(substr($packed, 64), true);
    $envelope[strlen($envelope) - 1] = chr(ord($envelope[strlen($envelope) - 1]) ^ 0xFF);

    DB::table('test_users')->where('id', $user->id)->update([
        'email' => substr($packed, 0, 64).base64_encode($envelope),
    ]);

    expect(fn () => TestUser::find($user->id)->email)
        ->toThrow(DecryptionFailed::class);
});

/*
|--------------------------------------------------------------------------
| Configuration guard
|--------------------------------------------------------------------------
*/

test('a column that is not configured is left untouched', function () {
    $user = TestUser::create([
        'name' => 'John Doe',
        'email' => 'john@example.com',
        'nickname' => 'johnny',
        'password' => 'secret-value',
    ]);

    // "nickname" is absent from crypto.fields, so it round trips as plain text
    // and is readable in the column without any decryption.
    expect($user->fresh()->nickname)->toBe('johnny')
        ->and(DB::table('test_users')->where('id', $user->id)->value('nickname'))->toBe('johnny');
});

test('an unconfigured column is not given the encrypted cast', function () {
    $casts = (fn () => $this->casts())->call(new TestUser);

    expect(array_keys($casts))->not->toContain('nickname')
        ->and(array_keys($casts))->toContain('email', 'name');
});

test('the cast is resolved through the container', function () {
    expect(Encrypted::castUsing([]))->toBeInstanceOf(Encrypted::class);
});

test('the cast coerces stringable values', function () {
    $user = new TestUser;

    expect(fn () => $user->name = new class implements Stringable
    {
        public function __toString(): string
        {
            return 'John Doe';
        }
    })->not->toThrow(InvalidArgumentException::class);
});

test('the cast is not an eloquent attribute object', function () {
    // Guards against a future refactor swapping CastsAttributes for an
    // Attribute-based implementation, which would change the semantics.
    expect(new Encrypted(app(CryptoService::class)))->not->toBeInstanceOf(Attribute::class);
});
