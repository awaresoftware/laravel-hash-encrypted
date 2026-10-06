<?php

namespace Aware\HashEncrypted\Auth;

use Aware\HashEncrypted\CryptoService;
use Aware\HashEncrypted\Database\BlindIndex;
use Closure;
use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Hashing\Hasher as HasherContract;
use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Arr;

/**
 * Resolves users through the blind index instead of comparing plaintext.
 *
 * Every credential that names a hash encrypted column is translated into a
 * blind index comparison before the query runs, which is what lets
 * Auth::attempt(), password resets and password confirmations keep working
 * against encrypted columns.
 */
class HashEncryptedUserProvider extends EloquentUserProvider
{
    /**
     * Create a new hash encrypted user provider instance.
     *
     * @param  class-string  $model
     */
    public function __construct(
        HasherContract $hasher,
        string $model,
        protected readonly CryptoService $crypto,
    ) {
        parent::__construct($hasher, $model);
    }

    /**
     * Retrieve a user by the given credentials, using blind indexes where possible.
     *
     * @param  array<string, mixed>  $credentials
     */
    public function retrieveByCredentials(#[\SensitiveParameter] array $credentials): ?Model
    {
        $credentials = array_filter(
            $credentials,
            fn ($key) => ! str_contains($key, 'password'),
            ARRAY_FILTER_USE_KEY,
        );

        if ($credentials === []) {
            return null;
        }

        $query = $this->newModelQuery();

        foreach ($credentials as $key => $value) {
            if (is_array($value) || $value instanceof Arrayable) {
                $values = array_filter(
                    Arr::wrap($value instanceof Arrayable ? $value->toArray() : $value),
                    is_string(...),
                );

                if ($values === []) {
                    return null;
                }

                if (BlindIndex::isEncryptedField($this->model, $key)) {
                    BlindIndex::whereIn($query, $this->model, $key, array_values($values));

                    continue;
                }

                $query->whereIn($key, $values);
            } elseif ($value instanceof Closure) {
                $value($query);
            } elseif (BlindIndex::isEncryptedField($this->model, $key) && (is_string($value) || is_numeric($value))) {
                BlindIndex::where($query, $this->model, $key, (string) $value);
            } else {
                $query->where($key, $value);
            }
        }

        $user = $query->first();

        return $user instanceof Authenticatable ? $user : null;
    }
}
