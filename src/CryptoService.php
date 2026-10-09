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
 * secret derived per field from the blind index key, so it can be compared for
 * equality (and indexed) without ever storing the plaintext, and the same
 * value produces unrelated blind indexes in different tables and columns.
 *
 * The envelope holds the plaintext encrypted with AES-256-GCM:
 *
 *   version (1 byte) │ key id (2 bytes) │ nonce (12 bytes) │ ciphertext │ tag (16 bytes)
 *
 * The envelope is authenticated with the field context as additional
 * authenticated data, and unpacking checks that the blind index in front of it
 * belongs to the decrypted plaintext, so neither half can be swapped on its own.
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
     * HMAC algorithms allowed for the blind index.
     */
    private const HASH_ALGORITHMS = ['sha256', 'sha384', 'sha512', 'sha3-256', 'sha3-384', 'sha3-512'];

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
     * The validated HMAC algorithm and blind index length, resolved on first use.
     *
     * @var array{string, int}|null
     */
    private ?array $blindIndexSettings = null;

    /**
     * The validated blind index key, resolved on first use.
     */
    private ?string $hashKey = null;

    /**
     * The blind index keys derived so far, keyed by field context.
     *
     * @var array<string, string>
     */
    private array $fieldKeys = [];

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
     * Get the blind index for the given plaintext in the given field.
     *
     * Two values that normalize to the same input always produce the same
     * blind index within one field, which is what makes the packed column
     * searchable. The HMAC key is derived per field, so the same value in two
     * different fields produces unrelated blind indexes.
     *
     * @param  string  $context  The field context, see context().
     */
    public function blindIndex(#[\SensitiveParameter] string $value, string $context): string
    {
        [$algorithm] = $this->blindIndexSettings();

        return hash_hmac($algorithm, $this->normalize($value), $this->fieldKey($context));
    }

    /**
     * Pack a plaintext value into a searchable, encrypted string.
     *
     * @param  string  $context  The field context, see context().
     */
    public function pack(#[\SensitiveParameter] string $plaintext, string $context): string
    {
        return $this->blindIndex($plaintext, $context).$this->encrypt($plaintext, $context);
    }

    /**
     * Unpack a value previously produced by pack().
     *
     * The blind index in front of the envelope is not covered by the
     * authentication tag, so it is recomputed from the decrypted plaintext and
     * compared: a row cannot carry one value's blind index and another value's
     * ciphertext.
     *
     * @param  string  $context  The field context, see context().
     *
     * @throws DecryptionFailed
     */
    public function unpack(#[\SensitiveParameter] string $packed, string $context): string
    {
        $plaintext = $this->decrypt($this->cipherText($packed), $context);

        if (! hash_equals(substr($packed, 0, $this->blindIndexLength()), $this->blindIndex($plaintext, $context))) {
            throw DecryptionFailed::unauthenticated();
        }

        return $plaintext;
    }

    /**
     * Decrypt a packed value and encrypt it again with the active key.
     *
     * This is the primitive behind the crypto:re-encrypt command. The blind
     * index is preserved because it is derived from the plaintext only.
     *
     * @throws DecryptionFailed
     */
    public function repack(#[\SensitiveParameter] string $packed, string $context): string
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
    public function isUnchanged(#[\SensitiveParameter] string $packed, #[\SensitiveParameter] string $plaintext, string $context): bool
    {
        if (! str_starts_with($packed, $this->blindIndex($plaintext, $context))) {
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
    public function keyIdOf(#[\SensitiveParameter] string $packed): int
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
    public function usesActiveKey(#[\SensitiveParameter] string $packed): bool
    {
        return $this->keyIdOf($packed) === $this->activeKeyId;
    }

    /**
     * Build the field context for a model column.
     *
     * The context is the additional authenticated data of the envelope and the
     * domain the blind index key is derived for, so it binds both halves of a
     * packed value to the field it belongs to.
     *
     * @param  class-string  $modelClass
     *
     * @throws RuntimeException When the template does not name the column.
     */
    public function context(string $modelClass, string $table, string $column): string
    {
        $template = (string) Config::get('crypto.aad', '{table}.{column}');

        if (! str_contains($template, '{column}')) {
            throw new RuntimeException('The crypto aad template must contain {column}, so that every column gets its own context.');
        }

        return str_replace(['{model}', '{table}', '{column}'], [$modelClass, $table, $column], $template);
    }

    /**
     * Encrypt a plaintext value into a base64 encoded envelope.
     */
    private function encrypt(#[\SensitiveParameter] string $plaintext, string $context): string
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
    private function decrypt(#[\SensitiveParameter] string $encoded, string $context): string
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
    private function keyIdFromEnvelope(#[\SensitiveParameter] string $raw): int
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
    private function cipherText(#[\SensitiveParameter] string $packed): string
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
    private function normalize(#[\SensitiveParameter] string $value): string
    {
        $normalized = mb_strtolower(trim($value));

        // ext-intl is a hard requirement: skipping NFC on some hosts would give
        // composed and decomposed input different blind indexes there.
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
        $activeKey = Config::get('crypto.encryption_key');

        if (! is_string($activeKey) || $activeKey === '') {
            throw new RuntimeException($this->missingKeyMessage('CRYPTO_ENCRYPTION_KEY'));
        }

        $keyring = [$this->resolveActiveKeyId() => $this->decodeKey($activeKey, 'CRYPTO_ENCRYPTION_KEY')];

        foreach ((array) Config::get('crypto.previous_encryption_keys', []) as $entry) {
            [$keyId, $key] = array_pad(explode(':', (string) $entry, 2), 2, null);

            if (! is_string($keyId) || ! ctype_digit($keyId) || ! is_string($key) || $key === '') {
                throw new RuntimeException('CRYPTO_PREVIOUS_KEYS must be a comma separated list of "keyId:key" pairs.');
            }

            $keyId = (int) $keyId;

            if ($keyId > 65535) {
                throw new RuntimeException('Every key id in CRYPTO_PREVIOUS_KEYS must be between 0 and 65535.');
            }

            // A reused id would silently replace a key: the active key would be
            // swapped for an old one, and a rotation would report success
            // without rotating anything.
            if (isset($keyring[$keyId])) {
                throw new RuntimeException("The key id [{$keyId}] is used more than once. Give every key in CRYPTO_ENCRYPTION_KEY_ID and CRYPTO_PREVIOUS_KEYS its own id.");
            }

            $keyring[$keyId] = $this->decodeKey($key, 'CRYPTO_PREVIOUS_KEYS');
        }

        $appKey = $this->appKey();

        foreach ($keyring as $key) {
            if ($appKey !== null && hash_equals($appKey, $key)) {
                throw new RuntimeException('The crypto encryption keys must be separate keys: none of them may equal APP_KEY.');
            }
        }

        return $keyring;
    }

    /**
     * Decode a base64 encoded 32 byte key.
     *
     * @throws RuntimeException
     */
    private function decodeKey(#[\SensitiveParameter] string $key, string $variable): string
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
     * Get the number of characters reserved for the blind index.
     *
     * @throws RuntimeException When it differs from the length of the configured HMAC.
     */
    public function blindIndexLength(): int
    {
        return $this->blindIndexSettings()[1];
    }

    /**
     * Get the validated HMAC algorithm and blind index length.
     *
     * The length must be exactly the hex length of the HMAC: a shorter
     * reservation would cut the blind index, and a longer one would pull random
     * ciphertext into the indexed prefix, where lookups never match and the
     * unique index enforces nothing.
     *
     * @return array{string, int}
     *
     * @throws RuntimeException
     */
    private function blindIndexSettings(): array
    {
        if ($this->blindIndexSettings !== null) {
            return $this->blindIndexSettings;
        }

        $algorithm = (string) Config::get('crypto.hash_algorithm', 'sha256');

        if (! in_array($algorithm, self::HASH_ALGORITHMS, true)) {
            throw new RuntimeException("The [{$algorithm}] hash algorithm is not allowed for the blind index. Use one of: ".implode(', ', self::HASH_ALGORITHMS).'.');
        }

        $length = (int) Config::get('crypto.blind_index_length', 64);
        $expected = strlen(hash($algorithm, ''));

        if ($length !== $expected) {
            throw new RuntimeException("The crypto blind index length [{$length}] must equal the length of a hex encoded [{$algorithm}] HMAC, which is {$expected} characters.");
        }

        return $this->blindIndexSettings = [$algorithm, $length];
    }

    /**
     * Get the blind index key derived for the given field.
     *
     * @throws RuntimeException
     */
    private function fieldKey(string $context): string
    {
        return $this->fieldKeys[$context] ??= hash_hkdf('sha256', $this->hashKey(), 32, 'awaresoftware/laravel-hash-encrypted:blind-index:'.$context);
    }

    /**
     * Get the validated key the field keys are derived from.
     *
     * @throws RuntimeException
     */
    private function hashKey(): string
    {
        if ($this->hashKey !== null) {
            return $this->hashKey;
        }

        $key = Config::get('crypto.hash_key');

        if (! is_string($key) || $key === '') {
            throw new RuntimeException($this->missingKeyMessage('CRYPTO_HASH_KEY'));
        }

        $decoded = $this->decodeKey($key, 'CRYPTO_HASH_KEY');

        foreach ([...array_values($this->keyring), $this->appKey()] as $other) {
            if ($other !== null && hash_equals($other, $decoded)) {
                throw new RuntimeException('The [CRYPTO_HASH_KEY] must be a separate key: it may not equal an encryption key or APP_KEY.');
            }
        }

        return $this->hashKey = $decoded;
    }

    /**
     * Get the decoded application key, so the crypto keys can be kept apart from it.
     */
    private function appKey(): ?string
    {
        $key = Config::get('app.key');

        if (! is_string($key) || $key === '') {
            return null;
        }

        $decoded = str_starts_with($key, 'base64:') ? base64_decode(substr($key, 7), true) : $key;

        return is_string($decoded) ? $decoded : null;
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
