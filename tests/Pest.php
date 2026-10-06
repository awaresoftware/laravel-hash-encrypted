<?php

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
