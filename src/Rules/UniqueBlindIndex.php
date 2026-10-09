<?php

namespace Aware\HashEncrypted\Rules;

use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Support\Str;
use Stringable;

/**
 * Validates that no other row holds the given plaintext in a hash encrypted column.
 *
 * This replaces Laravel's "unique:users,email" rule, which would compare
 * plaintext against ciphertext and therefore always pass. The comparison is an
 * index backed blind index lookup, so it is as cheap as a normal unique check.
 * The database still enforces uniqueness through the blind index unique
 * constraint, which closes the race between the validation and the insert.
 */
class UniqueBlindIndex implements ValidationRule
{
    /**
     * Create a new rule instance.
     *
     * @param  class-string  $model
     */
    public function __construct(
        protected readonly string $model,
        protected readonly string $column,
        protected readonly mixed $ignoreModelKey = null,
    ) {}

    /**
     * Run the validation rule.
     */
    public function validate(string $attribute, #[\SensitiveParameter] mixed $value, Closure $fail): void
    {
        if ($this->violates($value)) {
            $fail(__('validation.unique', ['attribute' => Str::snake($attribute)]));
        }
    }

    /**
     * Determine whether another row already stores the given plaintext.
     */
    public function violates(#[\SensitiveParameter] mixed $value): bool
    {
        // Coerce exactly as the Encrypted cast does, so a JSON number is checked
        // against the string the cast would store for it.
        if (is_scalar($value) || $value instanceof Stringable) {
            $value = (string) $value;
        }

        if (! is_string($value) || $value === '') {
            return false;
        }

        $query = $this->model::query()->whereEncrypted($this->column, $value);

        if ($this->ignoreModelKey !== null) {
            // whereKeyNot() only exists from Laravel 13.34 onwards, so the
            // portable equivalent is used to keep the package installable on
            // Laravel 11 and 12 as well.
            $query->where($query->getModel()->getQualifiedKeyName(), '!=', $this->ignoreModelKey);
        }

        return $query->exists();
    }
}
