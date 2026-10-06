<?php

namespace Aware\HashEncrypted\Database;

use Illuminate\Contracts\Database\Query\Expression as ExpressionContract;
use Illuminate\Database\Grammar;

/**
 * A SQL fragment that is safe to embed verbatim.
 *
 * Blind index lookups have to compare an expression over the column, which is
 * not something the query builder can build from a column name alone. The
 * fragment is assembled from the connection grammar, so identifiers are already
 * quoted and the comparison is always parameter bound for the blind index
 * itself. Wrapping it in a dedicated expression type keeps that guarantee
 * explicit instead of relying on a raw string.
 */
final class BlindIndexExpression implements ExpressionContract
{
    /**
     * Create a new expression from an already quoted SQL fragment.
     */
    public function __construct(private readonly string $sql) {}

    /**
     * Get the value of the expression.
     */
    public function getValue(Grammar $grammar): string
    {
        return $this->sql;
    }
}
