<?php

namespace Tests\HashEncrypted\Fixtures;

use Aware\HashEncrypted\Concerns\HasHashEncryptedFields;
use Illuminate\Database\Eloquent\Model;

/**
 * A second model with an encrypted column of the same name as TestUser's.
 *
 * It exists to prove that a blind index or a ciphertext from one table is
 * worthless in another table, even when both columns are called "email".
 *
 * @property int $id
 * @property string $email
 */
class TestContact extends Model
{
    use HasHashEncryptedFields;

    /**
     * The table associated with the model.
     *
     * @var string
     */
    protected $table = 'test_contacts';

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
        return $this->hashEncryptedCasts();
    }
}
