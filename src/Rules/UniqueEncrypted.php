<?php

namespace Aware\HashEncrypted\Rules;

use Illuminate\Contracts\Validation\Validator;
use Illuminate\Database\Eloquent\Model;

/**
 * Backs the "unique_encrypted" string rule.
 *
 * Prefer the UniqueBlindIndex rule object where a rule instance can be passed,
 * for example in a FormRequest or a Livewire component. This string rule exists
 * for the places where rules are written as strings only: shared rule strings,
 * configuration driven validation, and third party packages that build their
 * own rule sets.
 *
 * Usage:
 *
 *   'email' => 'required|email|max:255|unique_encrypted:'.User::class.',email'
 *   'email' => 'required|email|max:255|unique_encrypted:'.User::class.',email,'.$user->id
 *
 * The model class and column must be a configured hash encrypted field. The
 * third parameter ignores that model key, mirroring Rule::unique()->ignore().
 */
class UniqueEncrypted
{
    /**
     * Validate that no other row holds the given plaintext in the column.
     *
     * @param  array<int, mixed>  $parameters
     */
    public function __invoke(string $attribute, mixed $value, array $parameters, Validator $validator): bool
    {
        [$model, $column, $ignore] = array_pad($parameters, 3, null);

        if (! is_string($model) || ! is_subclass_of($model, Model::class) || ! is_string($column)) {
            return false;
        }

        return ! (new UniqueBlindIndex($model, $column, is_numeric($ignore) ? (int) $ignore : null))->violates($value);
    }
}
