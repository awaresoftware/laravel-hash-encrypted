<?php

namespace Aware\HashEncrypted\Console;

use Aware\HashEncrypted\CryptoService;
use Aware\HashEncrypted\Exceptions\DecryptionFailed;
use Illuminate\Console\Command;
use Illuminate\Console\View\TaskResult;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;

/**
 * Re-encrypts hash encrypted attributes with the active encryption key.
 *
 * This is the second half of a key rotation: the new key is added to the
 * configuration, the old one is moved to the previous keys list, and this
 * command rewrites the stored ciphertext. Blind indexes are derived from the
 * plaintext only, so they never change and remain searchable throughout.
 */
class ReEncryptCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'crypto:re-encrypt
                            {--model= : Limit the command to a single model class}
                            {--column= : Limit the command to a single attribute}
                            {--chunk=250 : Number of records to read per query}
                            {--force : Re-encrypt every record, even those already using the active key}
                            {--dry-run : Report what would be re-encrypted without writing}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Re-encrypt hash encrypted attributes with the active encryption key';

    /**
     * Execute the console command.
     */
    public function handle(CryptoService $crypto): int
    {
        $models = $this->models();

        if ($models === []) {
            $this->components->error('No models with hash encrypted attributes were found in the crypto configuration.');

            return self::FAILURE;
        }

        if ($this->option('dry-run')) {
            $this->components->info('Dry run: no values will be written.');
        }

        $force = (bool) $this->option('force');
        $chunk = max(1, (int) $this->option('chunk'));
        $failed = false;

        foreach ($models as $modelClass) {
            /** @var Model $model */
            $model = new $modelClass;

            foreach ($this->columns($model) as $column) {
                /** @var array{scanned: int, encrypted: int, changed: int, failed: int} $stats */
                $stats = ['scanned' => 0, 'encrypted' => 0, 'changed' => 0, 'failed' => 0];

                /** @var array<int, string> $failures */
                $failures = [];

                $this->components->task(
                    sprintf('Re-encrypting %s.%s', class_basename($model), $column),
                    function () use ($model, $column, $crypto, $chunk, $force, &$stats, &$failures): int {
                        $this->records($model, $column)
                            ->chunkById($chunk, function (Collection $records) use ($model, $column, $crypto, $force, &$stats, &$failures): bool {
                                foreach ($records as $record) {
                                    $stats['scanned']++;

                                    $packed = $record->getAttributes()[$column] ?? null;

                                    if (! is_string($packed) || $packed === '') {
                                        continue;
                                    }

                                    try {
                                        if (! $force && $crypto->usesActiveKey($packed)) {
                                            continue;
                                        }

                                        $repacked = $crypto->repack($packed, $crypto->context($model::class, $model->getTable(), $column));
                                    } catch (DecryptionFailed $exception) {
                                        $stats['failed']++;

                                        if (count($failures) < 10) {
                                            $failures[] = sprintf('%s #%s: %s', class_basename($model), $record->getKey(), $exception->getMessage());
                                        }

                                        continue;
                                    }

                                    if (! $this->option('dry-run') && ! $this->updateRecord($model, $column, (string) $record->getKey(), $packed, $repacked)) {
                                        $stats['changed']++;

                                        continue;
                                    }

                                    $stats['encrypted']++;
                                }

                                return true;
                                // Positional arguments only: the named "alias:"
                                // argument is not available on every supported
                                // Laravel version.
                            }, null, $model->getKeyName());

                        return $stats['failed'] > 0 ? TaskResult::Failure->value : TaskResult::Success->value;
                    },
                );

                foreach ($failures as $failure) {
                    $this->components->twoColumnDetail('Failed', $failure);
                }

                $this->components->twoColumnDetail(
                    sprintf('%d scanned, %d re-encrypted, %d changed concurrently, %d failed', $stats['scanned'], $stats['encrypted'], $stats['changed'], $stats['failed']),
                    $stats['failed'] > 0 ? '<fg=yellow;options=bold>Unresolved</>' : '<fg=green;options=bold>Done</>',
                );

                $failed = $failed || $stats['failed'] > 0;
            }
        }

        if ($failed) {
            $this->components->warn('Some records could not be re-encrypted. Resolve them before removing old keys from the configuration.');

            return self::FAILURE;
        }

        return self::SUCCESS;
    }

    /**
     * Get the models whose attributes should be re-encrypted.
     *
     * @return array<int, string>
     */
    protected function models(): array
    {
        $models = array_values(array_filter(
            array_keys((array) config('crypto.fields', [])),
            is_string(...),
        ));

        if (($only = $this->option('model')) !== null && $only !== '') {
            return in_array($only, $models, true) ? [$only] : [];
        }

        return $models;
    }

    /**
     * Get the hash encrypted attributes of the given model.
     *
     * @return array<int, string>
     */
    protected function columns(Model $model): array
    {
        $columns = (array) config('crypto.fields.'.$model::class, []);

        if (($only = $this->option('column')) !== null && $only !== '') {
            return in_array($only, $columns, true) ? [$only] : [];
        }

        return $columns;
    }

    /**
     * Build a query that streams the packed values without decrypting them.
     *
     * @return Builder<Model>
     */
    protected function records(Model $model, string $column): Builder
    {
        return $model->newQuery()->select([$model->getKeyName(), $column]);
    }

    /**
     * Write a single re-encrypted value, unless the row changed since it was read.
     *
     * The base query builder is used on purpose: casts are bypassed so the
     * already packed value is stored verbatim, and the "updated_at" timestamp
     * is left alone because re-encryption does not change the record's data.
     *
     * The update only applies while the column still holds the value that was
     * read, so a change the application made in the meantime is never reverted.
     * Such a row is already written with the active key.
     */
    protected function updateRecord(Model $model, string $column, string $key, string $original, string $packed): bool
    {
        return $model->newQuery()
            ->toBase()
            ->where($model->getKeyName(), $key)
            ->where($column, $original)
            ->update([$column => $packed]) > 0;
    }
}
