<?php

use Aware\HashEncrypted\CryptoService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\HashEncrypted\TestCase;

/*
|--------------------------------------------------------------------------
| Test Case
|--------------------------------------------------------------------------
|
| Every test, unit or feature, runs inside a booted testbench application: the
| CryptoService reads its keyring from the config repository in its constructor,
| so there is nothing useful to assert without an application around it.
|
| Feature tests additionally get a throwaway database seeded by the migration in
| tests/Fixtures/migrations, which builds its blind index lookups through the
| same CreatesBlindIndexes trait that applications use.
|
*/

pest()->extend(TestCase::class)->in('Unit', 'Feature');

pest()->use(RefreshDatabase::class)->in('Feature');

/**
 * Change the crypto configuration and drop the resolved service.
 *
 * The service validates its keys and blind index settings once and keeps them,
 * like a production process whose configuration never changes after boot. The
 * fixture migration already resolves it during set up, so a test that changes
 * the configuration has to start from a fresh instance.
 *
 * @param  array<string, mixed>  $values
 */
function configureCrypto(array $values): void
{
    config($values);

    app()->forgetInstance(CryptoService::class);
}
