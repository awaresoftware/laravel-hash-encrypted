<?php

namespace Aware\HashEncrypted\Exceptions;

use RuntimeException;

/**
 * Thrown whenever a hash encrypted value cannot be turned back into plaintext.
 *
 * This deliberately never reveals which step failed or what the value was, so
 * that error messages, logs and stack traces cannot leak sensitive data.
 */
final class DecryptionFailed extends RuntimeException
{
    /**
     * Create an exception for a value that does not have the expected layout.
     */
    public static function malformed(): static
    {
        return new self('The encrypted value is malformed.');
    }

    /**
     * Create an exception for a value whose authentication tag did not verify.
     */
    public static function unauthenticated(): static
    {
        return new self('The encrypted value could not be authenticated.');
    }

    /**
     * Create an exception for a value encrypted with an unknown key.
     */
    public static function unknownKey(int $keyId): static
    {
        return new self("The value is encrypted with the unknown key id [{$keyId}]. Is the key missing from the crypto configuration?");
    }

    /**
     * Create an exception for a value written by an unsupported envelope version.
     */
    public static function unsupportedVersion(int $version): static
    {
        return new self("The value uses the unsupported envelope version [{$version}].");
    }
}
