<?php

namespace Tests\HashEncrypted;

use Aware\HashEncrypted\HashEncryptedServiceProvider;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Foundation\Application;
use Orchestra\Testbench\TestCase as Orchestra;
use Tests\HashEncrypted\Fixtures\TestUser;

abstract class TestCase extends Orchestra
{
    /**
     * Get the package providers required by the tests.
     *
     * @param  Application  $app
     * @return array<int, class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [HashEncryptedServiceProvider::class];
    }

    /**
     * Define the environment the tests run in.
     *
     * The keys are set directly rather than through the environment so the
     * suite is hermetic and deterministic: blind index assertions depend on a
     * stable key.
     *
     * @param  Application  $app
     */
    protected function defineEnvironment($app): void
    {
        $this->configureDatabase($app['config']);

        $app['config']->set('crypto.encryption_key_id', 1);
        $app['config']->set('crypto.encryption_key', 'base64:'.base64_encode(str_repeat('a', 32)));
        $app['config']->set('crypto.hash_key', 'base64:'.base64_encode(str_repeat('b', 32)));
        $app['config']->set('crypto.fields', [
            TestUser::class => ['email', 'name'],
        ]);

        $app['config']->set('auth.providers.users', [
            'driver' => 'hash-encrypted',
            'model' => TestUser::class,
        ]);
    }

    /**
     * Configure the test database connection.
     *
     * SQLite in memory by default. The driver job in CI points DB_CONNECTION at a
     * real server, which is the only way the MariaDB prefix strategy and the
     * PostgreSQL functional index actually execute.
     */
    protected function configureDatabase(Repository $config): void
    {
        $driver = env('DB_CONNECTION', 'sqlite');

        $config->set('database.default', 'testing');

        $config->set('database.connections.testing', match ($driver) {
            'pgsql' => [
                'driver' => 'pgsql',
                'host' => env('DB_HOST', '127.0.0.1'),
                'port' => env('DB_PORT', '5432'),
                'database' => env('DB_DATABASE', 'testing'),
                'username' => env('DB_USERNAME', 'postgres'),
                'password' => env('DB_PASSWORD', ''),
                'charset' => 'utf8',
                'prefix' => '',
                'search_path' => 'public',
            ],
            'mysql', 'mariadb' => [
                'driver' => $driver,
                'host' => env('DB_HOST', '127.0.0.1'),
                'port' => env('DB_PORT', '3306'),
                'database' => env('DB_DATABASE', 'testing'),
                'username' => env('DB_USERNAME', 'root'),
                'password' => env('DB_PASSWORD', ''),
                'charset' => 'utf8mb4',
                'collation' => 'utf8mb4_unicode_ci',
                'prefix' => '',
                'strict' => true,
            ],
            default => [
                'driver' => 'sqlite',
                'database' => ':memory:',
                'prefix' => '',
            ],
        });
    }

    /**
     * Define the database migrations for the tests.
     */
    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(__DIR__.'/Fixtures/migrations');
    }
}
