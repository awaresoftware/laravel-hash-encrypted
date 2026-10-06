<?php

namespace Aware\HashEncrypted\Concerns;

use Aware\HashEncrypted\Casts\Encrypted;
use Aware\HashEncrypted\CryptoService;
use Aware\HashEncrypted\Database\BlindIndex;
use Illuminate\Database\Eloquent\Builder;

/**
 * Gives a model searchable, encrypted attributes.
 *
 * The attributes themselves are declared in the "crypto.fields"
 * configuration, keyed by model class, which keeps the encryption layout in
 * one place instead of scattering it across every model.
 */
trait HasHashEncryptedFields
{
    /**
     * Get the attributes of this model that are stored as a blind index plus ciphertext.
     *
     * @return array<int, string>
     */
    public function hashEncryptedFields(): array
    {
        return BlindIndex::fields(static::class);
    }

    /**
     * Determine whether the given attribute is stored as a blind index plus ciphertext.
     */
    public function hasHashEncryptedField(string $column): bool
    {
        return BlindIndex::isEncryptedField(static::class, $column);
    }

    /**
     * Get the searchable blind index for the given plaintext.
     */
    public function blindIndex(string $value): string
    {
        return app(CryptoService::class)->blindIndex($value);
    }

    /**
     * Build the Eloquent casts for the hash encrypted attributes.
     *
     * @return array<string, class-string>
     */
    protected function hashEncryptedCasts(): array
    {
        return array_fill_keys($this->hashEncryptedFields(), Encrypted::class);
    }

    /**
     * Scope the query to the row whose blind index matches the given plaintext.
     *
     * The comparison is index backed and case insensitive, but it is still an
     * exact match: partial and fuzzy searches are impossible by design.
     *
     * @param  Builder<static>  $query
     * @return Builder<static>
     */
    public function scopeWhereEncrypted(Builder $query, string $column, string $value): Builder
    {
        return BlindIndex::where($query, static::class, $column, $value);
    }

    /**
     * Scope the query to the rows whose blind index matches any of the given values.
     *
     * @param  Builder<static>  $query
     * @param  array<int, string>  $values
     * @return Builder<static>
     */
    public function scopeWhereEncryptedIn(Builder $query, string $column, array $values): Builder
    {
        return BlindIndex::whereIn($query, static::class, $column, $values);
    }
}
