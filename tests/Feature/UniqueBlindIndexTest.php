<?php

use Aware\HashEncrypted\Rules\UniqueBlindIndex;
use Aware\HashEncrypted\Rules\UniqueEncrypted;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Validator;
use Tests\HashEncrypted\Fixtures\TestUser;

beforeEach(function () {
    $this->user = TestUser::create([
        'name' => 'John Doe',
        'email' => 'john@example.com',
        'password' => 'password',
    ]);
});

/*
|--------------------------------------------------------------------------
| The rule object
|--------------------------------------------------------------------------
*/

test('the rule rejects a value that is already stored', function () {
    $rule = new UniqueBlindIndex(TestUser::class, 'email');

    expect($rule->violates('john@example.com'))->toBeTrue()
        ->and($rule->violates('nobody@example.com'))->toBeFalse();
});

test('the rule compares blind indexes, so it is case insensitive', function () {
    $rule = new UniqueBlindIndex(TestUser::class, 'email');

    expect($rule->violates('JOHN@EXAMPLE.COM'))->toBeTrue();
});

test('the rule ignores the given model key', function () {
    $rule = new UniqueBlindIndex(TestUser::class, 'email', $this->user->id);

    expect($rule->violates('john@example.com'))->toBeFalse();
});

test('the rule fails when a different model key holds the value', function () {
    TestUser::create([
        'name' => 'Jane Roe',
        'email' => 'jane@example.com',
        'password' => 'password',
    ]);

    $rule = new UniqueBlindIndex(TestUser::class, 'email', $this->user->id);

    expect($rule->violates('jane@example.com'))->toBeTrue();
});

test('the rule passes for an empty value', function () {
    $rule = new UniqueBlindIndex(TestUser::class, 'email');

    expect($rule->violates(''))->toBeFalse()
        ->and($rule->violates(null))->toBeFalse();
});

test('the rule fails loudly on a column that is not configured', function () {
    $rule = new UniqueBlindIndex(TestUser::class, 'password');

    expect(fn () => $rule->violates('password'))
        ->toThrow(InvalidArgumentException::class, 'is not configured as a hash encrypted field');
});

test('the rule reports a validation error through the validator', function () {
    $validator = Validator::make(
        ['email' => 'john@example.com'],
        ['email' => new UniqueBlindIndex(TestUser::class, 'email')],
    );

    expect($validator->fails())->toBeTrue()
        ->and($validator->errors()->first('email'))->toBe('The email has already been taken.');
});

/*
|--------------------------------------------------------------------------
| The string form
|--------------------------------------------------------------------------
*/

test('the string rule rejects a value that is already stored', function () {
    $validator = Validator::make(
        ['email' => 'john@example.com'],
        ['email' => 'unique_encrypted:'.TestUser::class.',email'],
    );

    expect($validator->fails())->toBeTrue();
});

test('the string rule passes for an unused value', function () {
    $validator = Validator::make(
        ['email' => 'nobody@example.com'],
        ['email' => 'unique_encrypted:'.TestUser::class.',email'],
    );

    expect($validator->fails())->toBeFalse();
});

test('the string rule ignores the model key given as a third parameter', function () {
    $validator = Validator::make(
        ['email' => 'john@example.com'],
        ['email' => 'unique_encrypted:'.TestUser::class.',email,'.$this->user->id],
    );

    expect($validator->fails())->toBeFalse();
});

test('the string rule rejects the string rule on a different model key', function () {
    $validator = Validator::make(
        ['email' => 'john@example.com'],
        ['email' => 'unique_encrypted:'.TestUser::class.',email,999'],
    );

    expect($validator->fails())->toBeTrue();
});

test('the string rule fails loudly on a column that is not configured', function () {
    $validator = Validator::make(
        ['email' => 'john@example.com'],
        ['email' => 'unique_encrypted:'.TestUser::class.',password'],
    );

    expect(fn () => $validator->fails())
        ->toThrow(InvalidArgumentException::class);
});

/*
|--------------------------------------------------------------------------
| Rule versus constraint
|--------------------------------------------------------------------------
*/

test('the database constraint rejects what validation can only warn about', function () {
    // The rule is advisory: two concurrent requests can both pass it and only
    // the unique blind index rejects the second write. The two are halves of
    // one guarantee, which is why the rule must not be the only line of defence.
    expect((new UniqueEncrypted)(
        'email',
        'john@example.com',
        [TestUser::class, 'email'],
        Validator::make([], []),
    ))->toBeFalse();

    // Nested in a transaction for the savepoint: PostgreSQL treats a constraint
    // violation as fatal to the entire transaction, so the connection has to be
    // returned to a usable state before the assertions after it can run.
    expect(fn () => DB::transaction(fn () => TestUser::create([
        'name' => 'Someone Else',
        'email' => 'JOHN@example.com',
        'password' => 'password',
    ])))->toThrow(UniqueConstraintViolationException::class);

    expect(TestUser::count())->toBe(1);
});

/*
|--------------------------------------------------------------------------
| Security regressions
|--------------------------------------------------------------------------
*/

test('the rule checks non string scalars exactly as the cast stores them', function () {
    // A JSON number used to pass as "unique" without a query, while the
    // cast stringified and stored it.
    TestUser::create(['name' => '12345', 'email' => 'numbers@example.com', 'password' => 'password']);

    $rule = new UniqueBlindIndex(TestUser::class, 'name');

    expect($rule->violates(12345))->toBeTrue()
        ->and($rule->violates(12345.0))->toBeTrue()
        ->and($rule->violates(12345.5))->toBeFalse()
        ->and($rule->violates(54321))->toBeFalse()
        ->and(Validator::make(['name' => 12345], ['name' => [$rule]])->fails())->toBeTrue();
})->group('security');
