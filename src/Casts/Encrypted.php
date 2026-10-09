<?php

namespace Aware\HashEncrypted\Casts;

use Aware\HashEncrypted\CryptoService;
use Illuminate\Contracts\Database\Eloquent\Castable;
use Illuminate\Contracts\Database\Eloquent\CastsAttributes;
use Illuminate\Database\Eloquent\Model;
use InvalidArgumentException;
use Stringable;

/**
 * Transparently packs a column into "blind index + AES-256-GCM ciphertext".
 *
 * Reading the attribute decrypts it, writing it re-encrypts it, and the
 * searchable prefix is kept in sync automatically. See CryptoService for the
 * packed layout.
 *
 * @implements CastsAttributes<string, string>
 */
final class Encrypted implements Castable, CastsAttributes
{
    /**
     * Create a new cast instance.
     */
    public function __construct(protected readonly CryptoService $crypto) {}

    /**
     * Resolve the cast, which is instantiated by the framework without going
     * through the container.
     *
     * @param  array<int, mixed>  $arguments
     * @return CastsAttributes<string, string>
     */
    public static function castUsing(array $arguments): CastsAttributes
    {
        return new self(app(CryptoService::class));
    }

    /**
     * Decrypt the value stored in the database.
     */
    public function get(Model $model, string $key, mixed $value, array $attributes): ?string
    {
        if ($value === null) {
            return null;
        }

        return $this->crypto->unpack(
            $this->stringValue($model, $key, $value),
            $this->context($model, $key),
        );
    }

    /**
     * Encrypt the value before it is stored in the database.
     *
     * Encryption is non deterministic, so an unchanged value would otherwise be
     * rewritten with fresh bytes on every single save. Keeping the stored value
     * as is also keeps the attribute clean of spurious changes, which matters
     * because callers such as the profile form check isDirty('email') to decide
     * whether the address changed and has to be verified again.
     */
    public function set(Model $model, string $key, #[\SensitiveParameter] mixed $value, array $attributes): ?string
    {
        if ($value === null) {
            return null;
        }

        $plaintext = $this->stringValue($model, $key, $value);
        $current = $attributes[$key] ?? null;

        if (is_string($current) && $this->crypto->isUnchanged($current, $plaintext, $this->context($model, $key))) {
            return $current;
        }

        return $this->crypto->pack($plaintext, $this->context($model, $key));
    }

    /**
     * Build the field context that binds a packed value to its table and column.
     */
    protected function context(Model $model, string $column): string
    {
        return $this->crypto->context($model::class, $model->getTable(), $column);
    }

    /**
     * Coerce the given value to the string the cast can handle.
     *
     * @throws InvalidArgumentException
     */
    protected function stringValue(Model $model, string $column, #[\SensitiveParameter] mixed $value): string
    {
        if (is_string($value)) {
            return $value;
        }

        if (is_scalar($value) || $value instanceof Stringable) {
            return (string) $value;
        }

        throw new InvalidArgumentException(sprintf(
            'The [%s] attribute of [%s] must be a string, [%s] given.',
            $column,
            $model::class,
            get_debug_type($value),
        ));
    }
}
