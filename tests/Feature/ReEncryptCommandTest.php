<?php

use Aware\HashEncrypted\Console\ReEncryptCommand;
use Aware\HashEncrypted\CryptoService;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Tests\HashEncrypted\Fixtures\TestUser;

beforeEach(function () {
    $this->user = TestUser::create([
        'name' => 'John Doe',
        'email' => 'john@example.com',
        'password' => 'password',
    ]);

    $this->original = $this->user->getRawOriginal('email');
});

/**
 * Rotate the configuration so new values use key id 2 and key id 1 becomes a
 * previous key.
 *
 * The service is a singleton whose keyring is built in its constructor, so the
 * resolved instance has to be dropped as well: in production the command runs in
 * a fresh process and never sees a stale instance, but a test that already
 * touched the container has one.
 */
function withPreviousKey(): void
{
    config([
        'crypto.encryption_key_id' => 2,
        'crypto.previous_encryption_keys' => ['1:'.config('crypto.encryption_key')],
        'crypto.encryption_key' => 'base64:'.base64_encode(random_bytes(32)),
    ]);

    app()->forgetInstance(CryptoService::class);
}

/*
|--------------------------------------------------------------------------
| Registration
|--------------------------------------------------------------------------
*/

test('the command is registered', function () {
    expect(array_keys(Artisan::all()))
        ->toContain('crypto:re-encrypt');
});

test('the command class is instantiable by the console kernel', function () {
    expect(new ReEncryptCommand)->toBeInstanceOf(Command::class);
});

/*
|--------------------------------------------------------------------------
| Rotation
|--------------------------------------------------------------------------
*/

test('rows on a previous key are re-encrypted and stay readable', function () {
    withPreviousKey();

    $this->artisan('crypto:re-encrypt')->assertSuccessful();

    $rotated = app(CryptoService::class);

    $stored = $this->user->fresh()->getRawOriginal('email');

    expect($rotated->keyIdOf($stored))->toBe(2)
        ->and($rotated->usesActiveKey($stored))->toBeTrue()
        ->and($this->user->fresh()->email)->toBe('john@example.com');
});

test('re-encryption preserves the blind index so lookups keep working', function () {
    withPreviousKey();

    $this->artisan('crypto:re-encrypt')->assertSuccessful();

    expect(TestUser::whereEncrypted('email', 'john@example.com')->count())->toBe(1)
        ->and($this->user->fresh()->getRawOriginal('email'))
        ->toStartWith(substr($this->original, 0, 64));
});

test('re-encryption does not touch the timestamps', function () {
    withPreviousKey();

    $before = $this->user->fresh()->updated_at;

    $this->artisan('crypto:re-encrypt')->assertSuccessful();

    expect($this->user->fresh()->updated_at->timestamp)->toBe($before->timestamp);
});

test('rows already on the active key are left alone', function () {
    $before = $this->user->fresh()->getRawOriginal('email');

    $this->artisan('crypto:re-encrypt')->assertSuccessful();

    expect($this->user->fresh()->getRawOriginal('email'))->toBe($before);
});

test('the force option re-encrypts every row', function () {
    $before = $this->user->fresh()->getRawOriginal('email');

    $this->artisan('crypto:re-encrypt', ['--force' => true])->assertSuccessful();

    // The blind index is stable but the ciphertext is not.
    expect($this->user->fresh()->getRawOriginal('email'))->not->toBe($before)
        ->and($this->user->fresh()->email)->toBe('john@example.com');
});

test('the dry run option writes nothing', function () {
    withPreviousKey();

    $before = $this->user->fresh()->getRawOriginal('email');

    $this->artisan('crypto:re-encrypt', ['--dry-run' => true])->assertSuccessful();

    expect($this->user->fresh()->getRawOriginal('email'))->toBe($before);
});

/*
|--------------------------------------------------------------------------
| Narrowing
|--------------------------------------------------------------------------
*/

test('the command can be limited to a single column', function () {
    withPreviousKey();

    $name = $this->user->fresh()->getRawOriginal('name');
    $email = $this->user->fresh()->getRawOriginal('email');

    $this->artisan('crypto:re-encrypt', ['--column' => 'name'])->assertSuccessful();

    expect($this->user->fresh()->getRawOriginal('name'))->not->toBe($name)
        ->and($this->user->fresh()->getRawOriginal('email'))->toBe($email);
});

test('the command can be limited to a single model', function () {
    withPreviousKey();

    $this->artisan('crypto:re-encrypt', ['--model' => TestUser::class])->assertSuccessful();

    expect(app(CryptoService::class)->keyIdOf($this->user->fresh()->getRawOriginal('email')))->toBe(2);
});

test('an unknown model is reported rather than silently doing nothing', function () {
    $this->artisan('crypto:re-encrypt', ['--model' => 'App\\Models\\Nope'])->assertFailed();
});

/*
|--------------------------------------------------------------------------
| Failure handling
|--------------------------------------------------------------------------
*/

test('an unreadable value fails the command and leaves the row untouched', function () {
    withPreviousKey();

    $before = $this->user->fresh()->getRawOriginal('email');

    // Retire key id 1 entirely, so the stored value can no longer be decrypted.
    // The command has to report the failure instead of silently moving on and
    // letting the operator drop the key from the configuration.
    config(['crypto.previous_encryption_keys' => []]);
    app()->forgetInstance(CryptoService::class);

    $this->artisan('crypto:re-encrypt')->assertFailed();

    expect($this->user->fresh()->getRawOriginal('email'))->toBe($before);
});

test('an empty table is not an error', function () {
    DB::table('test_users')->delete();

    $this->artisan('crypto:re-encrypt')->assertSuccessful();
});
