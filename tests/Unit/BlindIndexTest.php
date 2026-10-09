<?php

use Aware\HashEncrypted\CryptoService;
use Aware\HashEncrypted\Database\BlindIndex;
use Illuminate\Database\Connection;
use Illuminate\Database\MariaDbConnection;
use Illuminate\Database\MySqlConnection;
use Illuminate\Database\PostgresConnection;
use Illuminate\Database\SQLiteConnection;

/*
 * Connections are built without opening a PDO handle so the dialect specific
 * SQL can be asserted on every driver, including the ones CI cannot run
 * everywhere. The driver matrix job additionally runs the full suite against
 * live servers; these assertions pin the generated SQL itself.
 */
function blindIndexConnection(string $driver): Connection
{
    $never = fn (): never => throw new RuntimeException('No connection is expected to be opened.');

    return match ($driver) {
        'sqlite' => new SQLiteConnection($never, 'test', '', ['driver' => 'sqlite']),
        'mysql' => new MySqlConnection($never, 'test', '', ['driver' => 'mysql']),
        'mariadb' => new MariaDbConnection($never, 'test', '', ['driver' => 'mariadb']),
        'pgsql' => new PostgresConnection($never, 'test', '', ['driver' => 'pgsql']),
    };
}

beforeEach(function () {
    config(['crypto.blind_index_strategy' => 'auto']);
});

/*
|--------------------------------------------------------------------------
| Strategy selection
|--------------------------------------------------------------------------
*/

test('MariaDB falls back to a prefix index because it has no functional indexes', function (string $driver, string $expected) {
    expect(BlindIndex::strategy(blindIndexConnection($driver)))->toBe($expected);
})->with([
    ['sqlite', 'expression'],
    ['mysql', 'expression'],
    ['pgsql', 'expression'],
    ['mariadb', 'prefix_like'],
]);

test('the configured strategy overrides driver detection', function () {
    config(['crypto.blind_index_strategy' => 'prefix_like']);

    expect(BlindIndex::strategy(blindIndexConnection('sqlite')))->toBe('prefix_like');

    config(['crypto.blind_index_strategy' => 'expression']);

    expect(BlindIndex::strategy(blindIndexConnection('mariadb')))->toBe('expression');
});

/*
|--------------------------------------------------------------------------
| Lookup expressions
|--------------------------------------------------------------------------
*/

test('the lookup expression is dialect specific', function (string $driver, string $expected) {
    expect(BlindIndex::expression(blindIndexConnection($driver), 'email'))->toBe($expected);
})->with([
    ['sqlite', 'substr("email", 1, 64)'],
    ['pgsql', 'left("email", 64)'],
    ['mysql', 'LEFT(`email`, 64)'],
]);

test('the column is left unqualified so the planner matches the indexed expression', function () {
    // An expression index is only used when the query expression is textually
    // identical to the indexed one, and the index is defined on the bare column.
    expect(BlindIndex::expression(blindIndexConnection('sqlite'), 'email'))
        ->not->toContain('users.');
});

test('the expression follows the configured blind index length', function () {
    configureCrypto(['crypto.hash_algorithm' => 'sha512', 'crypto.blind_index_length' => 128]);

    expect(BlindIndex::expression(blindIndexConnection('sqlite'), 'email'))
        ->toBe('substr("email", 1, 128)');
});

test('a blind index length that does not match the algorithm never reaches the DDL', function () {
    // A mismatched prefix index would cover random ciphertext bytes.
    configureCrypto(['crypto.blind_index_length' => 96]);

    expect(fn () => BlindIndex::createIndexStatements(blindIndexConnection('sqlite'), 'users', ['email' => true]))
        ->toThrow(RuntimeException::class, 'must equal');
})->group('security');

test('a blind index length below 32 is rejected', function () {
    configureCrypto(['crypto.blind_index_length' => 16]);

    expect(fn () => BlindIndex::length())->toThrow(RuntimeException::class, 'must equal');
});

/*
|--------------------------------------------------------------------------
| Index DDL
|--------------------------------------------------------------------------
*/

test('a functional unique index is created on expression strategy drivers', function (string $driver, string $expected) {
    expect(BlindIndex::createIndexStatements(blindIndexConnection($driver), 'users', ['email' => true]))
        ->toBe([$expected]);
})->with([
    ['sqlite', 'CREATE UNIQUE INDEX "users_email_blind_index" ON "users" (substr("email", 1, 64))'],
    ['pgsql', 'CREATE UNIQUE INDEX "users_email_blind_index" ON "users" (left("email", 64))'],
    // MySQL expects a functional key part wrapped in an extra pair of parentheses,
    // on top of the parentheses that wrap the index key itself.
    ['mysql', 'CREATE UNIQUE INDEX `users_email_blind_index` ON `users` ((LEFT(`email`, 64)))'],
]);

test('a non unique column gets a plain index', function () {
    expect(BlindIndex::createIndexStatements(blindIndexConnection('sqlite'), 'users', ['name' => false]))
        ->toBe(['CREATE INDEX "users_name_blind_index" ON "users" (substr("name", 1, 64))']);
});

test('the prefix strategy creates a prefix index of the blind index length', function () {
    expect(BlindIndex::createIndexStatements(blindIndexConnection('mariadb'), 'users', ['email' => true]))
        ->toBe(['CREATE UNIQUE INDEX `users_email_blind_index` ON `users` (`email`(64))']);
});

test('the prefix index is exactly as wide as the blind index, so it stays unique', function () {
    // The packed value is blind_index(64) followed by the ciphertext envelope,
    // so the first 64 characters are the whole blind index. A unique prefix
    // index over those characters therefore enforces blind index uniqueness,
    // which is what makes MariaDB safe for a unique column.
    $crypto = app(CryptoService::class);

    $statement = BlindIndex::createIndexStatements(blindIndexConnection('mariadb'), 'users', ['email' => true])[0];

    expect($statement)->toContain('`email`(64)')
        ->and($statement)->toContain('UNIQUE')
        ->and(strlen($crypto->blindIndex('john@example.com', 'users.email')))->toBe(64);
});

test('one statement is returned per column', function () {
    $statements = BlindIndex::createIndexStatements(
        blindIndexConnection('sqlite'),
        'users',
        ['email' => true, 'name' => false],
    );

    expect($statements)->toHaveCount(2)
        ->and($statements[0])->toContain('users_email_blind_index')
        ->and($statements[1])->toContain('users_name_blind_index');
});
