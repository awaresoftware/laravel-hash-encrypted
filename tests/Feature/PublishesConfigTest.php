<?php

use Aware\HashEncrypted\CryptoService;
use Aware\HashEncrypted\HashEncryptedServiceProvider;
use Illuminate\Foundation\Application;

/*
|--------------------------------------------------------------------------
| Publishing
|--------------------------------------------------------------------------
*/

test('the configuration file can be published', function () {
    $target = config_path('crypto.php');

    @unlink($target);

    $this->artisan('vendor:publish', ['--tag' => 'hash-encrypted-config'])->assertSuccessful();

    expect(file_exists($target))->toBeTrue();

    @unlink($target);
});

test('the published file is the package configuration', function () {
    $target = config_path('crypto.php');

    @unlink($target);

    $this->artisan('vendor:publish', ['--tag' => 'hash-encrypted-config'])->assertSuccessful();

    $published = require $target;

    expect($published)->toHaveKeys(['encryption_key', 'hash_key', 'fields', 'version', 'cipher']);

    @unlink($target);
});

test('the published file ships no reference to a consuming application', function () {
    $target = config_path('crypto.php');

    @unlink($target);

    $this->artisan('vendor:publish', ['--tag' => 'hash-encrypted-config'])->assertSuccessful();

    // A config file that hardcoded an application model would break for every
    // other consumer the moment they installed the package.
    expect(file_get_contents($target))->not->toContain('App\\Models\\User');

    @unlink($target);
});

/*
|--------------------------------------------------------------------------
| Merge semantics
|--------------------------------------------------------------------------
*/

test('the package configuration is merged recursively into the application config', function () {
    // A shallow array_merge would replace the whole "crypto" key with the
    // application's copy, so any key the application does not set would vanish.
    // The recursive replace keeps the application's own values while filling in
    // everything else.
    //
    // With today's flat package config both strategies produce the same result.
    // The recursion is a forward looking guarantee: the first nested section
    // (the planned "search" subtree) would silently disappear under a shallow
    // merge, taking a key with it.
    config()->set('crypto', ['fields' => [], 'version' => 7]);

    (new HashEncryptedServiceProvider($this->app))->register();

    // The application's own value wins...
    expect(config('crypto.version'))->toBe(7)
        ->and(config('crypto.fields'))->toBe([]);

    // ...while every key it never mentioned keeps its package default.
    expect(config('crypto.cipher'))->toBe('aes-256-gcm')
        ->and(config('crypto.hash_algorithm'))->toBe('sha256')
        ->and(config('crypto.blind_index_length'))->toBe(64)
        ->and(config('crypto.blind_index_strategy'))->toBe('auto')
        ->and(config('crypto.hash_key'))->not->toBeNull();
});

test('the provider skips the merge when the configuration is cached', function () {
    // With a cached configuration the merge is skipped, exactly as Laravel's own
    // mergeConfigFrom() does, because the cached file already contains the merged
    // result from the moment it was built. Without the guard the merge would run
    // against the cached array and silently rebuild it on every request.
    config()->set('crypto', ['version' => 7]);

    $app = Mockery::mock(Application::class);
    $app->shouldReceive('configurationIsCached')->andReturnTrue();
    $app->shouldReceive('make')->never();
    $app->shouldReceive('singleton')->andReturnNull();
    $app->shouldReceive('runningInConsole')->andReturnFalse();

    (new HashEncryptedServiceProvider($app))->register();

    expect(config('crypto.version'))->toBe(7);
});

test('the crypto service is registered as a singleton', function () {
    expect(app(CryptoService::class))
        ->toBe(app(CryptoService::class));
});
