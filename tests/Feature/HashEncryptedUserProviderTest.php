<?php

use Aware\HashEncrypted\Auth\HashEncryptedUserProvider;
use Aware\HashEncrypted\CryptoService;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Tests\HashEncrypted\Fixtures\TestUser;

beforeEach(function () {
    $this->user = TestUser::create([
        'name' => 'John Doe',
        'email' => 'john@example.com',
        'password' => 'password',
    ]);

    $this->provider = new HashEncryptedUserProvider(
        Hash::driver(),
        TestUser::class,
        app(CryptoService::class),
    );
});

/*
|--------------------------------------------------------------------------
| Retrieval
|--------------------------------------------------------------------------
*/

test('a user is retrieved by an encrypted credential', function () {
    $found = $this->provider->retrieveByCredentials(['email' => 'john@example.com']);

    expect($found)->toBeInstanceOf(Authenticatable::class)
        ->and($found->id)->toBe($this->user->id);
});

test('retrieval is case insensitive', function () {
    expect($this->provider->retrieveByCredentials(['email' => '  JOHN@EXAMPLE.COM '])?->id)
        ->toBe($this->user->id);
});

test('an unknown credential returns null', function () {
    expect($this->provider->retrieveByCredentials(['email' => 'nobody@example.com']))->toBeNull();
});

test('multiple encrypted credentials are combined', function () {
    TestUser::create([
        'name' => 'John Doe',
        'email' => 'john@other.com',
        'password' => 'password',
    ]);

    $found = $this->provider->retrieveByCredentials([
        'name' => 'John Doe',
        'email' => 'john@example.com',
    ]);

    expect($found?->id)->toBe($this->user->id);
});

test('credentials are combined with AND, not OR', function () {
    TestUser::create([
        'name' => 'Jane Roe',
        'email' => 'jane@example.com',
        'password' => 'password',
    ]);

    // The name matches one row and the email matches another.
    expect($this->provider->retrieveByCredentials([
        'name' => 'Jane Roe',
        'email' => 'john@example.com',
    ]))->toBeNull();
});

test('an array credential matches any of its values', function () {
    expect($this->provider->retrieveByCredentials([
        'email' => ['nobody@example.com', 'john@example.com'],
    ])?->id)->toBe($this->user->id);
});

test('an empty array credential returns null', function () {
    expect($this->provider->retrieveByCredentials(['email' => []]))->toBeNull();
});

test('a plain column still compares normally', function () {
    $found = $this->provider->retrieveByCredentials(['id' => $this->user->id]);

    expect($found?->id)->toBe($this->user->id);
});

/*
|--------------------------------------------------------------------------
| Password handling
|--------------------------------------------------------------------------
*/

test('a password credential is never turned into a query', function () {
    // Passwords are checked by the hasher after retrieval, so including one in
    // the credential filter would compare a hash against a blind index.
    expect($this->provider->retrieveByCredentials([
        'email' => 'john@example.com',
        'password' => 'wrong-password',
    ])?->id)->toBe($this->user->id);
});

test('a credentials array with only a password returns null', function () {
    expect($this->provider->retrieveByCredentials(['password' => 'password']))->toBeNull();
});

test('an empty credentials array returns null', function () {
    expect($this->provider->retrieveByCredentials([]))->toBeNull();
});

/*
|--------------------------------------------------------------------------
| Driver registration
|--------------------------------------------------------------------------
*/

test('the driver is registered on the auth manager', function () {
    expect(Auth::getProvider('hash-encrypted'))->toBeInstanceOf(HashEncryptedUserProvider::class);
});

test('the driver reads its model from the auth configuration', function () {
    config(['auth.providers.users.model' => TestUser::class]);

    expect(Auth::createUserProvider('users'))->toBeInstanceOf(HashEncryptedUserProvider::class);
});

test('the provider still validates a password through the hasher', function () {
    $found = $this->provider->retrieveByCredentials(['email' => 'john@example.com']);

    expect($found)->not->toBeNull()
        ->and($this->provider->validateCredentials($found, ['password' => 'password']))->toBeTrue()
        ->and($this->provider->validateCredentials($found, ['password' => 'wrong']))->toBeFalse();
});
