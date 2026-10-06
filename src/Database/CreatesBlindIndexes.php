<?php

namespace Aware\HashEncrypted\Database;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/**
 * Creates the lookup indexes for hash encrypted columns inside a migration.
 *
 * The indexes cannot be declared as ordinary schema builder indexes: a lookup
 * compares an expression over the column, so the indexed part has to be a
 * functional index on "expression" strategy drivers, or a prefix index on
 * MariaDB. Both are emitted as raw DDL, which is why this is a helper called
 * after the table is created rather than a fluent call inside Schema::create():
 * inside that closure the table does not exist yet, so the index would be
 * emitted before the CREATE TABLE statement.
 *
 * The DDL is generated from the same helper the query scopes use, so the lookup
 * expression and the indexed expression cannot drift apart.
 *
 * Usage:
 *
 *   return new class extends Migration
 *   {
 *       use CreatesBlindIndexes;
 *
 *       public function up(): void
 *       {
 *           Schema::create('users', function (Blueprint $table) {
 *               $table->id();
 *               $table->text('email');
 *           });
 *
 *           $this->createBlindIndexes('users', ['email' => true]);
 *       }
 *   };
 */
trait CreatesBlindIndexes
{
    /**
     * Create the blind index indexes for the given columns.
     *
     * @param  array<string, bool>  $columns  Column name mapped to whether it must be unique.
     */
    protected function createBlindIndexes(string $table, array $columns): void
    {
        $connection = $this->connectionName()
            ? DB::connection($this->connectionName())
            : DB::connection();

        foreach (BlindIndex::createIndexStatements($connection, $table, $columns) as $statement) {
            $connection->statement($statement);
        }
    }

    /**
     * Get the name of the migration's connection, if it declares one.
     */
    protected function connectionName(): ?string
    {
        return property_exists($this, 'connection') ? $this->connection : null;
    }
}