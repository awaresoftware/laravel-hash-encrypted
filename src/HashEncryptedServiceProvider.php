<?php

namespace Aware\HashEncrypted;

use Aware\HashEncrypted\Auth\HashEncryptedUserProvider;
use Aware\HashEncrypted\Console\ReEncryptCommand;
use Aware\HashEncrypted\Rules\UniqueEncrypted;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Foundation\CachesConfiguration;
use Illuminate\Contracts\Validation\Validator as ValidatorContract;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\ServiceProvider;

/**
 * Wires the package into a Laravel application.
 *
 * The package deliberately registers nothing that depends on a specific
 * authentication stack, so it works with Fortify, Sanctum, Breeze or a bare
 * application. The only integration surface is the "hash-encrypted" user
 * provider driver, which is opt-in from the consuming config/auth.php.
 */
class HashEncryptedServiceProvider extends ServiceProvider
{
    /**
     * Register any package services.
     */
    public function register(): void
    {
        $this->registerConfig();

        $this->app->singleton(CryptoService::class);

        if ($this->app->runningInConsole()) {
            $this->registerPublishing();
        }
    }

    /**
     * Bootstrap any package services.
     */
    public function boot(): void
    {
        $this->registerValidationRules();
        $this->registerUserProvider();
        $this->registerCommands();
    }

    /**
     * Merge the package defaults into the application configuration.
     *
     * replaceConfigRecursivelyFrom() is preferred over mergeConfigFrom() because
     * the latter is a shallow array_merge: an application that published
     * config/crypto.php once would keep its own file verbatim forever, and any
     * key added by a later release would silently disappear instead of picking up
     * its new default. The recursive variant still lets the application's values
     * win per key, while filling in keys it does not know about.
     *
     * It is written out rather than delegating to
     * ServiceProvider::replaceConfigRecursivelyFrom(), because that method is not
     * available on every Laravel version this package supports.
     */
    protected function registerConfig(): void
    {
        $app = $this->app;

        if ($app instanceof CachesConfiguration && $app->configurationIsCached()) {
            return;
        }

        $config = $app->make('config');

        $config->set('crypto', array_replace_recursive(
            require __DIR__.'/../config/crypto.php',
            $config->get('crypto', []),
        ));
    }

    /**
     * Register the publishable configuration file.
     */
    protected function registerPublishing(): void
    {
        $this->publishes([
            __DIR__.'/../config/crypto.php' => config_path('crypto.php'),
        ], 'hash-encrypted-config');
    }

    /**
     * Register the string form of the hash encrypted uniqueness rule.
     *
     * Uniqueness of an encrypted column cannot be expressed with the stock
     * "unique:users,email" rule, because it would compare plaintext against
     * ciphertext. This offers the same ergonomics as a string rule while
     * comparing blind indexes:
     *
     *   'email' => 'unique_encrypted:'.User::class.',email,'.$user->id
     */
    protected function registerValidationRules(): void
    {
        Validator::extend(
            'unique_encrypted',
            fn (string $attribute, mixed $value, array $parameters, ValidatorContract $validator): bool => app(UniqueEncrypted::class)(
                $attribute,
                $value,
                $parameters,
                $validator,
            ),
            'The :attribute has already been taken.',
        );
    }

    /**
     * Register the user provider that resolves rows by their blind index.
     *
     * Enable it from config/auth.php:
     *
     *   'providers' => [
     *       'users' => ['driver' => 'hash-encrypted', 'model' => User::class],
     *   ],
     */
    protected function registerUserProvider(): void
    {
        Auth::provider('hash-encrypted', function (Application $app, array $config) {
            return new HashEncryptedUserProvider(
                $app->make('hash'),
                $config['model'] ?? $app->make(ConfigRepository::class)->get('auth.providers.users.model'),
                $app->make(CryptoService::class),
            );
        });
    }

    /**
     * Register the package console commands.
     */
    protected function registerCommands(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([ReEncryptCommand::class]);
        }
    }
}
