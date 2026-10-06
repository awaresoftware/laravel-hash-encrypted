<?php

use Aware\HashEncrypted\CryptoService;
use Aware\HashEncrypted\Database\BlindIndex;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Tests\HashEncrypted\Fixtures\TestUser;

beforeEach(function () {
    $this->user = TestUser::create([
        'name' => 'John Doe',
        'email' => 'john@example.com',
        'password' => 'password',
    ]);

    $this->other = TestUser::create([
        'name' => 'Jane Roe',
        'email' => 'jane@example.com',
        'password' => 'password',
    ]);
});

/*
|--------------------------------------------------------------------------
| Exact lookups
|--------------------------------------------------------------------------
*/

test('a row is found by an encrypted attribute', function () {
    $found = TestUser::whereEncrypted('email', 'john@example.com')->first();

    expect($found->id)->toBe($this->user->id)
        ->and($found->email)->toBe('john@example.com');
});

test('a row is found by a second encrypted attribute', function () {
    expect(TestUser::whereEncrypted('name', 'Jane Roe')->first()->email)->toBe('jane@example.com');
});

test('lookups are case and whitespace insensitive', function () {
    expect(TestUser::whereEncrypted('email', '  JOHN@Example.COM ')->count())->toBe(1);
});

test('lookups can be combined', function () {
    TestUser::create([
        'name' => 'John Doe',
        'email' => 'john@other.com',
        'password' => 'password',
    ]);

    expect(
        TestUser::whereEncrypted('name', 'John Doe')->whereEncrypted('email', 'john@example.com')->count()
    )->toBe(1);
});

test('a lookup does not match a different row', function () {
    expect(TestUser::whereEncrypted('email', 'nobody@example.com')->count())->toBe(0);
});

test('whereEncryptedIn matches any of the given values', function () {
    $ids = TestUser::whereEncryptedIn('email', ['john@example.com', 'jane@example.com'])
        ->pluck('id')
        ->all();

    expect($ids)->toContain($this->user->id, $this->other->id)
        ->and($ids)->toHaveCount(2);
});

test('whereEncryptedIn with an empty list matches nothing', function () {
    expect(TestUser::whereEncryptedIn('email', [])->count())->toBe(0);
});

test('whereEncryptedIn is case insensitive', function () {
    expect(TestUser::whereEncryptedIn('email', ['JOHN@EXAMPLE.COM'])->count())->toBe(1);
});

/*
|--------------------------------------------------------------------------
| Guards
|--------------------------------------------------------------------------
*/

test('querying a column that is not configured is rejected', function () {
    expect(fn () => TestUser::whereEncrypted('password', 'secret')->get())
        ->toThrow(InvalidArgumentException::class, 'is not configured as a hash encrypted field');
});

test('querying an unconfigured column through whereEncryptedIn is rejected', function () {
    expect(fn () => TestUser::whereEncryptedIn('password', ['secret'])->get())
        ->toThrow(InvalidArgumentException::class);
});

test('the guard names the configuration key to fix', function () {
    expect(fn () => TestUser::whereEncrypted('password', 'secret')->get())
        ->toThrow(InvalidArgumentException::class, 'crypto.fields');
});

/*
|--------------------------------------------------------------------------
| Index backed uniqueness
|--------------------------------------------------------------------------
*/

test('the blind index is unique in the database', function () {
    // Encryption is non deterministic, so only an index on the blind index can
    // enforce this. Two values differing only in case normalise to the same
    // blind index and must collide.
    //
    // The insert runs inside a nested transaction so it gets a savepoint:
    // PostgreSQL treats a constraint violation as fatal to the whole
    // transaction, which would make the count below impossible to query.
    expect(fn () => DB::transaction(fn () => TestUser::create([
        'name' => 'Someone Else',
        'email' => 'JOHN@example.com',
        'password' => 'password',
    ])))->toThrow(QueryException::class);

    expect(TestUser::count())->toBe(2);
});

test('a non unique encrypted column accepts duplicates', function () {
    // "name" has a plain, non unique blind index, so two rows may hold the same
    // value. The emails still have to differ, because email is unique.
    TestUser::create([
        'name' => 'John Doe',
        'email' => 'one@example.com',
        'password' => 'password',
    ]);

    TestUser::create([
        'name' => 'John Doe',
        'email' => 'two@example.com',
        'password' => 'password',
    ]);

    expect(TestUser::whereEncrypted('name', 'John Doe')->count())->toBe(3);
});

/*
|--------------------------------------------------------------------------
| Index existence
|--------------------------------------------------------------------------
*/

test('the blind index indexes exist on the table', function () {
    $names = collect(Schema::getIndexes('test_users'))->pluck('name');

    expect($names)->toContain('test_users_email_blind_index', 'test_users_name_blind_index');
});

test('the email blind index is unique', function () {
    $indexes = collect(Schema::getIndexes('test_users'))->keyBy('name');

    expect($indexes['test_users_email_blind_index']['unique'])->toBeTrue()
        ->and($indexes['test_users_name_blind_index']['unique'])->toBeFalse();
});

/*
|--------------------------------------------------------------------------
| Query shape
|--------------------------------------------------------------------------
*/

/**
 * Run a lookup and return the query it produced.
 */
function captureEncryptedLookup(): QueryExecuted
{
    $queries = [];

    DB::listen(function ($query) use (&$queries): void {
        $queries[] = $query;
    });

    TestUser::whereEncrypted('email', 'john@example.com')->get();

    return end($queries);
}

function lookupStrategy(): string
{
    return BlindIndex::strategy(TestUser::query()->getModel()->getConnection());
}

test('the blind index is always bound and never interpolated into the SQL text', function () {
    // The security invariant that has to hold on every driver and under both
    // strategies: the blind index is a secret derived value, so it travels as a
    // parameter. Interpolating it would leak into query logs.
    $query = captureEncryptedLookup();
    $blindIndex = app(CryptoService::class)->blindIndex('john@example.com');

    expect($query->sql)->not->toContain($blindIndex)
        ->and($query->bindings)->toHaveCount(1)
        ->and($query->bindings[0])->toStartWith($blindIndex);
});

test('the expression strategy compares against the indexed expression', function () {
    if (lookupStrategy() !== 'expression') {
        $this->markTestSkipped('This driver uses the prefix_like strategy.');
    }

    $connection = TestUser::query()->getModel()->getConnection();
    $query = captureEncryptedLookup();

    expect($query->sql)->toContain(BlindIndex::expression($connection, 'email'))
        ->and($query->bindings)->toBe([app(CryptoService::class)->blindIndex('john@example.com')]);
});

test('the prefix strategy compares with LIKE and binds the blind index as a prefix', function () {
    if (lookupStrategy() !== 'prefix_like') {
        $this->markTestSkipped('This driver uses the expression strategy.');
    }

    $query = captureEncryptedLookup();

    // The prefix index only gets used by the planner when the comparison is a
    // prefix LIKE, so the wildcard has to be part of the bound value.
    expect(strtolower($query->sql))->toContain('like')
        ->and($query->bindings)->toBe([app(CryptoService::class)->blindIndex('john@example.com').'%']);
});

test('a malicious value cannot break out of the blind index comparison', function () {
    $queries = [];

    DB::listen(function ($query) use (&$queries): void {
        $queries[] = $query;
    });

    TestUser::whereEncrypted('email', "' OR 1=1 --")->get();

    $query = end($queries);

    expect($query->sql)->not->toContain('1=1')
        ->and($query->bindings)->toHaveCount(1)
        ->and(TestUser::count())->toBe(2);
});
