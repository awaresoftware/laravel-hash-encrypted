<?php

namespace Aware\HashEncrypted;

use Aware\HashEncrypted\Exceptions\DecryptionFailed;
use Illuminate\Support\Facades\Config;
use Normalizer;
use RuntimeException;

/**
 * Packs a plaintext value into a single searchable database value.
 *
 * A packed value is a fixed width blind index followed by a base64 encoded
 * envelope, which keeps it pure ASCII and therefore safe to store in a TEXT
 * column, to compare, and to index:
 *
 *   ┌──────────────────────────────────────────────────────────────┐
 *   │ blind index (64 chars)          │ base64 envelope (variable) │
 *   └──────────────────────────────────────────────────────────────┘
 *
 * The blind index is an HMAC of the normalized plaintext, keyed with a
 * secret, so it can be compared for equality (and indexed) without ever
 * storing the plaintext.
 *
 * The envelope holds the plaintext encrypted with AES-256-GCM:
 *
 *   version (1 byte) │ key id (2 bytes) │ nonce (12 bytes) │ ciphertext │ tag (16 bytes)
 *
 * Version and key id live inside the base64 payload so that the leading
 * blind index keeps a fixed width and stays indexable, while still allowing
 * the encryption key to be rotated (see crypto:re-encrypt) and the envelope
 * layout to evolve.
 */
class CryptoService
{
    /**
     * Bytes reserved in front of the nonce: version (1) and key id (2).
     */
    private const HEADER_BYTES = 3;

    /**
     * Number of random bytes prefixed to every ciphertext.
     */
    private const NONCE_BYTES = 12;

    /**
     * Length of the AES-GCM authentication tag, in bytes.
     */
    private const TAG_BYTES = 16;

    /**
     * The active key id mapped to its decoded 32 byte key.
     *
     * @var array<int, string>
     */
    private array $keyring;

    /**
     * The id of the key new values are encrypted with.
     */
    private readonly int $activeKeyId;

    /**
     * Create a new crypto service instance.
     *
     * @throws RuntimeException When a configured key is missing or invalid.
     */
    public function __construct()
    {
        $this->keyring = $this->resolveKeyring();
        $this->activeKeyId = $this->resolveActiveKeyId();
    }

    /**
     * Get the blind index for the given plaintext.
     *
     * Two values that normalize to the same input always produce the same
     * blind index, which is what makes the packed column searchable.
     */
    public function blindIndex(string $value): string
    {
        return hash_hmac(
            $this->hashAlgorithm(),
            $this->normalize($value),
            $this->hashKey(),
        );
    }

    /**
     * Pack a plaintext value into a searchable, encrypted string.
     *
     * @param  string  $context  Additional authenticated data, usually the column name.
     */
    public function pack(string $plaintext, string $context = ''): string
    {
        return $this->blindIndex($plaintext).$this->encrypt($plaintext, $context);
    }

    /**
     * Unpack a value previously produced by pack().
     *
     * @param  string  $context  Additional authenticated data, usually the column name.
     *
     * @throws DecryptionFailed
     */
    public function unpack(string $packed, string $context = ''): string
    {
        return $this->decrypt($this->cipherText($packed), $context);
    }

    /**
     * Decrypt a packed value and encrypt it again with the active key.
     *
     * This is the primitive behind the crypto:re-encrypt command. The blind
     * index is preserved because it is derived from the plaintext only.
     *
     * @throws DecryptionFailed
     */
    public function repack(string $packed, string $context = ''): string
    {
        return $this->pack($this->unpack($packed, $context), $context);
    }

    /**
     * Determine whether a packed value already holds exactly the given plaintext.
     *
     * Encryption is non deterministic, so re-encrypting an unchanged value
     * would rewrite the column with fresh bytes on every save. The cast uses
     * this to keep the stored value untouched, which in turn keeps the model
     * clean of spurious changes.
     */
    public function isUnchanged(string $packed, string $plaintext, string $context = ''): bool
    {
        if (! str_starts_with($packed, $this->blindIndex($plaintext))) {
            return false;
        }

        try {
            return $this->unpack($packed, $context) === $plaintext;
        } catch (DecryptionFailed) {
            return false;
        }
    }

    /**
     * Get the id of the key a packed value was encrypted with.
     *
     * @throws DecryptionFailed
     */
    public function keyIdOf(string $packed): int
    {
        $raw = base64_decode($this->cipherText($packed), true);

        if (! is_string($raw)) {
            throw DecryptionFailed::malformed();
        }

        return $this->keyIdFromEnvelope($raw);
    }

    /**
     * Determine whether a packed value is encrypted with the active key.
     *
     * @throws DecryptionFailed
     */
    public function usesActiveKey(string $packed): bool
    {
        return $this->keyIdOf($packed) === $this->activeKeyId;
    }

    /**
     * Build the additional authenticated data for a model column.
     *
     * @param  class-string  $modelClass
     */
    public function context(string $modelClass, string $column): string
    {
        return str_replace(
            ['{model}', '{column}'],
            [$modelClass, $column],
            (string) Config::get('crypto.aad', '{column}'),
        );
    }

    /**
     * Encrypt a plaintext value into a base64 encoded envelope.
     */
    private function encrypt(string $plaintext, string $context): string
    {
        $keyId = $this->activeKeyId;
        $nonce = random_bytes(self::NONCE_BYTES);
        $tag = '';

        $ciphertext = openssl_encrypt(
            $plaintext,
            $this->cipher(),
            $this->keyFor($keyId),
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            $context,
            self::TAG_BYTES,
        );

        if (! is_string($ciphertext)) {
            throw new RuntimeException('Unable to encrypt the value.');
        }

        return base64_encode(chr($this->version()).pack('n', $keyId).$nonce.$ciphertext.$tag);
    }

    /**
     * Decrypt a base64 encoded envelope.
     *
     * @throws DecryptionFailed
     */
    private function decrypt(string $encoded, string $context): string
    {
        $raw = base64_decode($encoded, true);

        if (! is_string($raw) || strlen($raw) < self::HEADER_BYTES + self::NONCE_BYTES + self::TAG_BYTES) {
            throw DecryptionFailed::malformed();
        }

        $version = ord($raw[0]);

        if ($version !== $this->version()) {
            throw DecryptionFailed::unsupportedVersion($version);
        }

        $nonce = substr($raw, self::HEADER_BYTES, self::NONCE_BYTES);
        $tag = substr($raw, -self::TAG_BYTES);
        $ciphertext = substr($raw, self::HEADER_BYTES + self::NONCE_BYTES, -self::TAG_BYTES);

        $plaintext = openssl_decrypt(
            $ciphertext,
            $this->cipher(),
            $this->keyFor($this->keyIdFromEnvelope($raw)),
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            $context,
        );

        if (! is_string($plaintext)) {
            throw DecryptionFailed::unauthenticated();
        }

        return $plaintext;
    }

    /**
     * Read the key id from a decoded envelope.
     *
     * @throws DecryptionFailed
     */
    private function keyIdFromEnvelope(string $raw): int
    {
        if (strlen($raw) < self::HEADER_BYTES) {
            throw DecryptionFailed::malformed();
        }

        $unpacked = unpack('n', substr($raw, 1, 2));

        if (! is_array($unpacked)) {
            throw DecryptionFailed::malformed();
        }

        return (int) $unpacked[1];
    }

    /**
     * Get the encrypted portion of a packed value.
     *
     * @throws DecryptionFailed
     */
    private function cipherText(string $packed): string
    {
        $length = $this->blindIndexLength();

        if (strlen($packed) <= $length) {
            throw DecryptionFailed::malformed();
        }

        return substr($packed, $length);
    }

    /**
     * Normalize a value before it is blinded, so that lookups stay case and
     * whitespace insensitive.
     */
    private function normalize(string $value): string
    {
        $normalized = mb_strtolower(trim($value));

        if (! class_exists(Normalizer::class)) {
            return $normalized;
        }

        return Normalizer::normalize($normalized, Normalizer::FORM_C) ?: $normalized;
    }

    /**
     * Build the keyring from the configuration.
     *
     * @return array<int, string>
     *
     * @throws RuntimeException
     */
    private function resolveKeyring(): array
    {
        $keyring = [];
        $activeKey = Config::get('crypto.encryption_key');

        if (is_string($activeKey) && $activeKey !== '') {
            $keyring[$this->resolveActiveKeyId()] = $this->decodeKey($activeKey, 'CRYPTO_ENCRYPTION_KEY');
        }

        foreach ((array) Config::get('crypto.previous_encryption_keys', []) as $entry) {
            [$keyId, $key] = array_pad(explode(':', (string) $entry, 2), 2, null);

            if (! is_numeric($keyId) || ! is_string($key) || $key === '') {
                throw new RuntimeException('CRYPTO_PREVIOUS_KEYS must be a comma separated list of "keyId:key" pairs.');
            }

            $keyring[(int) $keyId] = $this->decodeKey($key, 'CRYPTO_PREVIOUS_KEYS');
        }

        if ($keyring === []) {
            throw new RuntimeException($this->missingKeyMessage('CRYPTO_ENCRYPTION_KEY'));
        }

        return $keyring;
    }

    /**
     * Decode a base64 encoded 32 byte key.
     *
     * @throws RuntimeException
     */
    private function decodeKey(string $key, string $variable): string
    {
        $decoded = base64_decode(str_starts_with($key, 'base64:') ? substr($key, 7) : $key, true);

        if (! is_string($decoded) || strlen($decoded) !== 32) {
            throw new RuntimeException($this->missingKeyMessage($variable));
        }

        return $decoded;
    }

    /**
     * Get the decoded key for the given key id.
     *
     * @throws DecryptionFailed
     */
    private function keyFor(int $keyId): string
    {
        return $this->keyring[$keyId] ?? throw DecryptionFailed::unknownKey($keyId);
    }

    /**
     * Get the id of the key new values are encrypted with.
     */
    private function resolveActiveKeyId(): int
    {
        $keyId = (int) Config::get('crypto.encryption_key_id', 1);

        if ($keyId < 0 || $keyId > 65535) {
            throw new RuntimeException('The crypto encryption key id must be between 0 and 65535.');
        }

        return $keyId;
    }

    /**
     * Get the configured envelope version.
     */
    private function version(): int
    {
        $version = (int) Config::get('crypto.version', 1);

        if ($version < 1 || $version > 255) {
            throw new RuntimeException('The crypto envelope version must be between 1 and 255.');
        }

        return $version;
    }

    /**
     * Get the configured cipher.
     */
    private function cipher(): string
    {
        $cipher = (string) Config::get('crypto.cipher', 'aes-256-gcm');

        if ($cipher !== 'aes-256-gcm') {
            throw new RuntimeException('The crypto cipher must be [aes-256-gcm] so that tampered values are detected.');
        }

        return $cipher;
    }

    /**
     * Get the configured HMAC algorithm.
     */
    private function hashAlgorithm(): string
    {
        $algorithm = (string) Config::get('crypto.hash_algorithm', 'sha256');

        if (! in_array($algorithm, hash_hmac_algos(), true)) {
            throw new RuntimeException("The [{$algorithm}] hash algorithm is not supported by this PHP installation.");
        }

        return $algorithm;
    }

    /**
     * Get the number of characters reserved for the blind index.
     */
    private function blindIndexLength(): int
    {
        $length = (int) Config::get('crypto.blind_index_length', 64);

        if ($length < 32) {
            throw new RuntimeException('The crypto blind index length must be at least 32 characters.');
        }

        return $length;
    }

    /**
     * Get the key used to blind values.
     *
     * @throws RuntimeException
     */
    private function hashKey(): string
    {
        $key = Config::get('crypto.hash_key');

        if (! is_string($key) || $key === '') {
            throw new RuntimeException($this->missingKeyMessage('CRYPTO_HASH_KEY'));
        }

        return $this->decodeKey($key, 'CRYPTO_HASH_KEY');
    }

    /**
     * Build an actionable message for a misconfigured key.
     */
    private function missingKeyMessage(string $variable): string
    {
        return "The [{$variable}] environment variable is missing or invalid. It must be a base64 encoded 32 byte key. Generate one with: ".
            'php -r "echo \'base64:\' . base64_encode(random_bytes(32)) . PHP_EOL;"';
    }
}
