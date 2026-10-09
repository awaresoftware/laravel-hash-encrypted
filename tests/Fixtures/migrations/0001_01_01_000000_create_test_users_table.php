<?php

use Aware\HashEncrypted\Database\CreatesBlindIndexes;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    use CreatesBlindIndexes;

    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('test_users', function (Blueprint $table) {
            $table->id();

            // TEXT, because a packed value is 64 characters of blind index plus
            // roughly 1.4x the plaintext length.
            $table->text('name');
            $table->text('email');
            $table->string('nickname')->nullable();
            $table->string('password');
            $table->timestamps();
        });

        $this->createBlindIndexes('test_users', ['email' => true, 'name' => false]);

        // A second table with a same-named encrypted column, used to prove that
        // blind indexes and ciphertexts are bound to their table.
        Schema::create('test_contacts', function (Blueprint $table) {
            $table->id();
            $table->text('email');
            $table->timestamps();
        });

        $this->createBlindIndexes('test_contacts', ['email' => true]);
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('test_contacts');
        Schema::dropIfExists('test_users');
    }
};
