<?php

namespace Aware\HashEncrypted\Database;

use Aware\HashEncrypted\CryptoService;
use Illuminate\Database\Connection;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Config;
use InvalidArgumentException;

/**
 * Driver aware helpers for the searchable prefix of a hash encrypted column.
 *
 * The lookup strategy has to match the index that was created for the column,
 * otherwise the database falls back to a full table scan. That is why the DDL
 * used by the migration and the SQL used by the query scopes are generated from
 * the same place.
 */
final class BlindIndex
{
    /**
     * Get the hash encrypted attributes configured for the given model.
     *
     * @param  class-string  $modelClass
     * @return array<int, string>
     */
    public static function fields(string $modelClass): array
    {
        return (array) Config::get("crypto.fields.{$modelClass}", []);
    }

    /**
     * Determine whether the given model column is stored as a blind index plus ciphertext.
     *
     * @param  class-string  $modelClass
     */
    public static function isEncryptedField(string $modelClass, string $column): bool
    {
        return in_array($column, self::fields($modelClass), true);
    }

    /**
     * Get the lookup strategy for the given connection.
     *
     * @return string either "expression" or "prefix_like"
     */
    public static function strategy(Connection $connection): string
    {
        $configured = (string) Config::get('crypto.blind_index_strategy', 'auto');

        if (in_array($configured, ['expression', 'prefix_like'], true)) {
            return $configured;
        }

        return match ($connection->getDriverName()) {
            // MariaDB has no functional indexes, so a prefix index combined with
            // a LIKE comparison is the only way to get an index backed lookup.
            'mariadb' => 'prefix_like',
            default => 'expression',
        };
    }

    /**
     * Build the SQL expression that extracts the blind index from a column.
     *
     * The column is intentionally left unqualified: an expression index is only
     * used by the planner when the query expression matches the indexed
     * expression exactly, and the index is defined on the bare column.
     */
    public static function expression(Connection $connection, string $column): string
    {
        $wrapped = $connection->getQueryGrammar()->wrap($column);
        $length = self::length();

        return match ($connection->getDriverName()) {
            'sqlite' => "substr({$wrapped}, 1, {$length})",
            'pgsql' => "left({$wrapped}, {$length})",
            default => "LEFT({$wrapped}, {$length})",
        };
    }

    /**
     * Build the CREATE INDEX statements for the given columns.
     *
     * @param  array<string, bool>  $columns  Column name mapped to whether it must be unique.
     * @return array<int, string>
     */
    public static function createIndexStatements(Connection $connection, string $table, array $columns): array
    {
        $grammar = $connection->getQueryGrammar();
        $prefixIndex = self::strategy($connection) === 'prefix_like';

        $statements = [];

        foreach ($columns as $column => $unique) {
            $key = $prefixIndex
                ? $grammar->wrap($column).'('.self::length().')'
                : self::indexKey($connection, $column);

            $statements[] = sprintf(
                'CREATE %sINDEX %s ON %s (%s)',
                $unique ? 'UNIQUE ' : '',
                $grammar->wrap("{$table}_{$column}_blind_index"),
                $grammar->wrapTable($table),
                $key,
            );
        }

        return $statements;
    }

    /**
     * Constrain a query to the row whose blind index matches the given plaintext.
     *
     * @template TModel of Model
     *
     * @param  Builder<TModel>  $query
     * @param  class-string  $modelClass
     * @return Builder<TModel>
     */
    public static function where(Builder $query, string $modelClass, string $column, #[\SensitiveParameter] string $value): Builder
    {
        self::guard($modelClass, $column);

        $connection = self::connectionFor($query);
        $blindIndex = self::blindIndex($query->getModel(), $column, $value);

        if (self::strategy($connection) === 'prefix_like') {
            return $query->where($column, 'LIKE', $blindIndex.'%');
        }

        return $query->whereRaw(
            new BlindIndexExpression(self::expression($connection, $column).' = ?'),
            [$blindIndex],
        );
    }

    /**
     * Constrain a query to the rows whose blind index matches any of the given values.
     *
     * @template TModel of Model
     *
     * @param  Builder<TModel>  $query
     * @param  class-string  $modelClass
     * @param  array<int, string>  $values
     * @return Builder<TModel>
     */
    public static function whereIn(Builder $query, string $modelClass, string $column, #[\SensitiveParameter] array $values): Builder
    {
        self::guard($modelClass, $column);

        $connection = self::connectionFor($query);
        $model = $query->getModel();
        $blindIndexes = array_map(fn (string $value): string => self::blindIndex($model, $column, $value), $values);

        if ($blindIndexes === []) {
            return $query->whereRaw(
                new BlindIndexExpression(self::expression($connection, $column).' = ?'),
                [''],
            );
        }

        if (self::strategy($connection) === 'prefix_like') {
            return $query->where(function (Builder $query) use ($column, $blindIndexes): void {
                foreach ($blindIndexes as $blindIndex) {
                    $query->orWhere($column, 'LIKE', $blindIndex.'%');
                }
            });
        }

        return $query->whereIn(
            new BlindIndexExpression(self::expression($connection, $column)),
            $blindIndexes,
        );
    }

    /**
     * Get the connection of the given query as the concrete class the SQL helpers need.
     *
     * @template TModel of Model
     *
     * @param  Builder<TModel>  $query
     */
    private static function connectionFor(Builder $query): Connection
    {
        return $query->getModel()->getConnection();
    }

    /**
     * Get the number of characters reserved for the blind index.
     *
     * The crypto service validates it against the configured HMAC algorithm, so
     * the indexes a migration creates always cover exactly the blind index.
     */
    public static function length(): int
    {
        return app(CryptoService::class)->blindIndexLength();
    }

    /**
     * Build the index key for a column, taking dialect specific rules into account.
     */
    private static function indexKey(Connection $connection, string $column): string
    {
        $expression = self::expression($connection, $column);

        // MySQL expects functional key parts to be wrapped in an extra pair of
        // parentheses, while SQLite and PostgreSQL expect a bare expression.
        return $connection->getDriverName() === 'mysql'
            ? "({$expression})"
            : $expression;
    }

    /**
     * Get the blind index for the given plaintext in a model column.
     */
    public static function blindIndex(Model $model, string $column, #[\SensitiveParameter] string $value): string
    {
        $crypto = app(CryptoService::class);

        return $crypto->blindIndex($value, $crypto->context($model::class, $model->getTable(), $column));
    }

    /**
     * Ensure the column is actually configured as a hash encrypted field.
     *
     * @param  class-string  $modelClass
     */
    private static function guard(string $modelClass, string $column): void
    {
        if (! self::isEncryptedField($modelClass, $column)) {
            throw new InvalidArgumentException(
                "The [{$column}] attribute of [{$modelClass}] is not configured as a hash encrypted field. ".
                'Add it to the [crypto.fields] configuration before querying it.'
            );
        }
    }
}
