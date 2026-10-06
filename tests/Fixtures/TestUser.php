<?php

namespace Tests\HashEncrypted\Fixtures;

use Aware\HashEncrypted\Concerns\HasHashEncryptedFields;
use Illuminate\Foundation\Auth\User as Authenticatable;

/**
 * A minimal authenticatable model with hash encrypted columns.
 *
 * Deliberately built on the framework's base authenticatable rather than on any
 * application's User model, so the package suite never depends on the
 * application it was extracted from.
 *
 * @property int $id
 * @property string $name
 * @property string $email
 * @property string|null $nickname
 * @property string $password
 */
class TestUser extends Authenticatable
{
    use HasHashEncryptedFields;

    /**
     * The table associated with the model.
     *
     * @var string
     */
    protected $table = 'test_users';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $guarded = [];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'password' => 'hashed',
            ...$this->hashEncryptedCasts(),
        ];
    }
}
