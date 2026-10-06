# aware/hash-encrypted

Searchable, encrypted columns for Laravel.

A column can be both **encrypted at rest** and **indexed and searchable**, which
normally is impossible: ciphertext is opaque, so the database cannot compare it.
This package stores each value as a fixed width **blind index** followed by an
**AES-256-GCM ciphertext** in one column. The blind index is an HMAC of the
plaintext under a secret key, so equality lookups and unique constraints work
normally, while the plaintext is never stored.

```
┌──────────────────────────────────────────────────────────────┐
│ blind index (64 chars)          │ base64 envelope (variable) │
└──────────────────────────────────────────────────────────────┘
```

The envelope holds the encrypted value:

```
version (1) │ key id (2) │ nonce (12) │ ciphertext │ tag (16)
```

Version and key id live *inside* the base64 payload, so the blind index keeps a
fixed width and stays indexable while the encryption key can still be rotated
without invalidating every lookup.

---

## Requirements

- PHP 8.3+
- Laravel 11, 12 or 13
- Any of SQLite, PostgreSQL, MySQL 8.0.13+ or MariaDB

## Installation

```bash
composer require aware/hash-encrypted
```

### 1. Generate the keys

Two independent secrets. They must not be the same value, and both must be
backed up with the rest of your application secrets: **losing `CRYPTO_HASH_KEY`
makes every stored value neither decryptable nor findable.**

```bash
php -r "echo 'CRYPTO_ENCRYPTION_KEY=' . 'base64:' . base64_encode(random_bytes(32)) . PHP_EOL;"
php -r "echo 'CRYPTO_HASH_KEY='      . 'base64:' . base64_encode(random_bytes(32)) . PHP_EOL;"
```

```
CRYPTO_ENCRYPTION_KEY_ID=1
CRYPTO_ENCRYPTION_KEY=base64:...
CRYPTO_HASH_KEY=base64:...
```

### 2. Declare your encrypted columns

In your `AppServiceProvider::register()`:

```php
use Illuminate\Support\Facades\Config;

Config::set('crypto.fields', [
    User::class => ['email', 'name'],
]);
```

`register()` is the right place: it runs after the package provider has merged
the package defaults, so this value reliably wins.

### 3. Use the trait on your model

```php
use Aware\HashEncrypted\Concerns\HasHashEncryptedFields;

class User extends Authenticatable
{
    use HasHashEncryptedFields;

    protected function casts(): array
    {
        return [
            'password' => 'hashed',
            ...$this->hashEncryptedCasts(),
        ];
    }
}
```

### 4. Create the table and its lookup indexes

The columns are `TEXT`: a packed value is 64 characters of blind index plus
roughly 1.4× the plaintext length.

The lookup index cannot be an ordinary schema builder index, because a lookup
compares an *expression* over the column. Use the migration trait:

```php
use Aware\HashEncrypted\Database\CreatesBlindIndexes;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    use CreatesBlindIndexes;

    public function up(): void
    {
        Schema::create('users', function (Blueprint $table) {
            $table->id();
            $table->text('name');
            $table->text('email');
            $table->timestamps();
        });

        // Column name mapped to whether the index must be unique.
        $this->createBlindIndexes('users', ['email' => true, 'name' => false]);
    }

    public function down(): void
    {
        Schema::dropIfExists('users');
    }
};
```

This has to run **after** the table is created. Inside the `Schema::create()`
closure the table does not exist yet, so the index would be emitted before the
`CREATE TABLE`.

### 5. Enable the user provider

```php
// config/auth.php
'providers' => [
    'users' => [
        'driver' => 'hash-encrypted',
        'model' => App\Models\User::class,
    ],
],
```

---

## Usage

Reading and writing need no changes: the cast encrypts on write and decrypts on
read.

### Lookups

```php
User::whereEncrypted('email', 'john@example.com')->first();
User::whereEncryptedIn('email', $emails)->get();
```

Lookups are **exact** and case/whitespace insensitive (`trim`, `mb_strtolower`,
NFC). They are index backed and the blind index travels as a bound parameter,
never interpolated into SQL.

> Exact match is the limit by design. Partial, `LIKE '%…'` and fuzzy searches
> are impossible from a single blind index, because it covers the whole value.
> Do not attempt them: they will silently scan and decrypt every row.

### Validation

Plain `unique:users,email` compares plaintext against ciphertext and therefore
always passes. Use the rule object, or its string form:

```php
use Aware\HashEncrypted\Rules\UniqueBlindIndex;

public function rules(): array
{
    return [
        'email' => [
            'required',
            'email',
            new UniqueBlindIndex(User::class, 'email', $this->user?->id),
        ],
    ];
}
```

```php
// String form, for shared rule strings and config driven validation:
'email' => 'required|email|unique_encrypted:'.User::class.',email,'.$user->id
```

The rule is **advisory**. The real guarantee is the unique blind index in the
database: two concurrent requests can both pass validation, and only the
constraint rejects the second write. Treat a `UniqueConstraintViolationException`
as a validation error so the race stays a form error instead of a 500.

---

## Driver support

| Driver | Strategy | Lookup | Unique |
|---|---|---|---|
| SQLite | `expression` | `substr(col, 1, 64)` functional index | yes |
| PostgreSQL | `expression` | `left(col, 64)` functional index | yes |
| MySQL 8.0.13+ | `expression` | `LEFT(col, 64)` functional index | yes |
| MySQL < 8.0.13 | `prefix_like` | `col(64)` prefix index + `LIKE 'blind-index%'` | yes |
| MariaDB | `prefix_like` | `col(64)` prefix index + `LIKE 'blind-index%'` | yes |

MariaDB and older MySQL have no functional indexes, so the prefix strategy is
used instead. It is safe: the prefix is created over exactly the blind index
length, and the blind index is the first thing in the packed value, so a unique
prefix index still rejects duplicates.

Detection is automatic. Override it with `CRYPTO_BLIND_INDEX_STRATEGY` if a
managed database reports itself differently.

---

## Key rotation

Encryption keys rotate without touching the blind index, because the blind index
is derived from the plaintext alone. Every lookup keeps working throughout.

1. Move the current key to `CRYPTO_PREVIOUS_KEYS`, keeping its key id:
   ```
   CRYPTO_PREVIOUS_KEYS=1:base64:AAA...
   ```
2. Generate a new key and assign it a **new** id in `CRYPTO_ENCRYPTION_KEY`,
   with `CRYPTO_ENCRYPTION_KEY_ID=2`.
3. Re-encrypt stored values:
   ```bash
   php artisan crypto:re-encrypt --dry-run   # report first
   php artisan crypto:re-encrypt
   ```
4. Once every row uses the new key, drop the old key from the list.

The command exits non-zero and lists unresolved records if any value cannot be
decrypted. Do not remove a previous key until it reports success.

`CRYPTO_HASH_KEY` is rotated differently, and much more painfully: changing it
changes every blind index, which makes existing rows unfindable. Rotation
requires re-encrypting and re-indexing the whole table, so plan it as a
maintenance operation rather than a routine one.

---

## Threat model

**An attacker with read access to the database, without `CRYPTO_HASH_KEY`, learns:**

- which rows share a value (the blind index is deterministic), so duplicate
  counts and equality classes
- the ciphertext length, which bounds the plaintext length
- nothing else

**They do not learn** the plaintext, the ordering of values (the sort key is the
blind index, so `ORDER BY email` is effectively random), or whether two
different columns hold the same value — unless they can also query them through
the application.

**Assumptions and limits:**

- The blind index key must stay secret. A plain SHA-256 of an email address is
  trivially reversible with a word list; an HMAC under a secret is not.
- Do not index low entropy values or values whose *existence* is itself
  sensitive (tokens, account identifiers). Equality is still exposed.
- `DecryptionFailed` never reveals which step failed or what the value was, so
  error messages, logs and stack traces do not leak plaintext.
- AAD binds each ciphertext to its column, so a value cannot be moved to another
  column and still decrypt.

### Fortify and password resets

Fortify is **not** a dependency of this package. To keep a plaintext address out
of `password_reset_tokens`, return the blind index from the model:

```php
public function getEmailForPasswordReset(): string
{
    return $this->blindIndex((string) $this->email);
}
```

> The reset token table then stores a **raw blind index**, not a packed value,
> while `users.email` holds a packed value. That works only because Fortify never
> decrypts the token row. Do not "normalise" it: doing so writes every requested
> password reset address straight back into the database.

If the reset URL has to carry a readable address, bind it explicitly:

```php
ResetPassword::createUrlUsing(function (CanResetPassword $notifiable, string $token): string {
    return url(route('password.reset', [
        'token' => $token,
        'email' => $notifiable->getAttribute(Fortify::email()),
    ], absolute: false));
});
```

### Rate limiter keys

Fortify's login throttle key is built from the submitted identifier and persisted
in the cache store, which would otherwise hold every attempted address in
plaintext. Derive it from the blind index instead:

```php
use Aware\HashEncrypted\CryptoService;
use Laravel\Fortify\LoginRateLimiter;

class HashEncryptedLoginRateLimiter extends LoginRateLimiter
{
    protected function throttleKey(Request $request): string
    {
        $identifier = $request->input(Fortify::username());

        $blindIndex = is_string($identifier) && $identifier !== ''
            ? app(CryptoService::class)->blindIndex($identifier)
            : '';

        return $blindIndex.'|'.$request->ip();
    }
}
```

---

## Configuration

Most applications never need the config file. If you do:

```bash
php artisan vendor:publish --tag=hash-encrypted-config
```

| Key | Default | Purpose |
|---|---|---|
| `encryption_key_id` | `1` | Id of the active key, stored in every envelope. `0`–`65535`. |
| `encryption_key` | `null` | Base64 32 byte AES-256-GCM key. |
| `previous_encryption_keys` | `[]` | `"id:key"` pairs, comma separated. |
| `hash_key` | `null` | Base64 32 byte key behind the blind index. |
| `hash_algorithm` | `sha256` | HMAC algorithm for the blind index. |
| `cipher` | `aes-256-gcm` | Must stay `aes-256-gcm` so tampering is detected. |
| `blind_index_length` | `64` | Leading characters reserved for the blind index. Minimum `32`. |
| `version` | `1` | Envelope version. Raise only when the layout changes. |
| `aad` | `{column}` | Additional authenticated data template, supports `{model}` and `{column}`. |
| `fields` | `[]` | Which attributes are stored encrypted, keyed by model class. |
| `blind_index_strategy` | `auto` | `auto`, `expression` or `prefix_like`. |

The package merges its defaults **recursively**, so a published config keeps
working when a later release adds new keys: your values still win, but keys you
never set receive their new default.

---

## Testing

```bash
composer test
```

## License

MIT. See [LICENSE.md](LICENSE.md).