<?php

namespace WebGuardian\Scanner;

class LaravelScanner
{
    private string $path;
    private array $options;

    private const SENSITIVE_FILES = [
        '.env',
        'config/app.php',
        'config/database.php',
        'config/auth.php',
        'config/mail.php',
        'config/services.php',
    ];

    private const DANGEROUS_ROUTES = [
        '/_ignition', '/debugbar', '/telescope', '/horizon',
        '/nova', '/admin', '/api/documentation',
    ];

    public function __construct(string $path, array $options = [])
    {
        $this->path = $path;
        $this->options = $options;
    }

    public function scan(): array
    {
        $findings = [];

        $findings = array_merge($findings, $this->checkEnvFile());
        $findings = array_merge($findings, $this->checkAppDebug());
        $findings = array_merge($findings, $this->checkRouteExposure());
        $findings = array_merge($findings, $this->checkProviders());
        $findings = array_merge($findings, $this->checkMiddleware());
        $findings = array_merge($findings, $this->checkStorageSymlink());
        $findings = array_merge($findings, $this->checkComposerPackages());

        return $findings;
    }

    private function checkEnvFile(): array
    {
        $findings = [];
        $envFile = $this->path . '/.env';

        if (!file_exists($envFile)) {
            $findings[] = [
                'file'     => $this->path,
                'line'     => 0,
                'pattern'  => 'missing_env',
                'severity' => 'high',
                'type'     => 'laravel',
                'message'  => '.env file not found. Application may not be properly configured.',
            ];
            return $findings;
        }

        // Check if .env is publicly accessible (common misconfiguration)
        $publicEnv = $this->path . '/public/.env';
        if (file_exists($publicEnv)) {
            $findings[] = [
                'file'     => $publicEnv,
                'line'     => 0,
                'pattern'  => 'env_in_public',
                'severity' => 'critical',
                'type'     => 'laravel',
                'message'  => '.env found in public directory - credentials exposed to the web',
            ];
        }

        $content = file_get_contents($envFile);
        if ($content === false) return $findings;

        $lines = explode("\n", $content);

        // Check for weak/common credentials
        $weakPatterns = [
            '/^DB_PASSWORD\s*=\s*["\']?$/'                         => 'Empty database password',
            '/^DB_PASSWORD\s*=\s*["\']?root["\']?$/i'             => 'Default database password (root)',
            '/^DB_PASSWORD\s*=\s*["\']?password["\']?$/i'         => 'Weak database password (password)',
            '/^DB_PASSWORD\s*=\s*["\']?secret["\']?$/i'           => 'Weak database password (secret)',
            '/^DB_PASSWORD\s*=\s*["\']?123456["\']?$/i'           => 'Weak database password (123456)',
            '/^APP_KEY\s*=\s*["\']?$/'                            => 'Missing APP_KEY',
            '/^APP_KEY\s*=\s*["\']?base64:[A-Za-z0-9+\/]{10,20}=["\']?$/i' => 'APP_KEY appears too short - may be weak',
            '/^APP_KEY\s*=\s*["\']?SomeRandomKey["\']?$/i'        => 'Default APP_KEY value',
            '/^APP_KEY\s*=\s*["\']?ChangeMeBy32CharactersLong?["\']?$/i' => 'Default APP_KEY placeholder',
        ];

        foreach ($lines as $lineNum => $line) {
            $line = trim($line);
            if (str_starts_with($line, '#')) continue;

            foreach ($weakPatterns as $pattern => $message) {
                if (preg_match($pattern, $line)) {
                    $findings[] = [
                        'file'     => $envFile,
                        'line'     => $lineNum + 1,
                        'pattern'  => 'weak_env_credential',
                        'severity' => 'critical',
                        'type'     => 'laravel',
                        'message'  => $message,
                    ];
                }
            }

            // Check for hardcoded credentials in env
            foreach (['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'MAIL_PASSWORD', 'DB_PASSWORD'] as $key) {
                if (str_starts_with($line, $key)) {
                    $value = substr($line, strlen($key) + 1);
                    $value = trim($value, '"\' ');
                    if ($value !== '' && !in_array(strtolower($value), ['null', 'false', 'true'])) {
                        // It exists and has a value - that's normally fine, but check if it's exposed elsewhere
                    }
                }
            }
        }

        return $findings;
    }

    private function checkAppDebug(): array
    {
        $findings = [];
        $configApp = $this->path . '/config/app.php';

        if (!file_exists($configApp)) return $findings;

        $content = file_get_contents($configApp);
        if (!$content) return $findings;

        // Check if debug is true
        if (preg_match('/[\'"]debug[\'"]\s*=>\s*env\s*\(\s*[\'"]APP_DEBUG[\'"]\s*,\s*true\s*\)/', $content) ||
            preg_match('/[\'"]debug[\'"]\s*=>\s*true/', $content)) {
            $findings[] = [
                'file'     => $configApp,
                'line'     => 0,
                'pattern'  => 'debug_mode',
                'severity' => 'high',
                'type'     => 'laravel',
                'message'  => 'APP_DEBUG is enabled or defaults to true. This can expose sensitive information in production.',
            ];
        }

        return $findings;
    }

    private function checkRouteExposure(): array
    {
        $findings = [];
        $routesFile = $this->path . '/routes/web.php';
        $apiRoutes  = $this->path . '/routes/api.php';

        $routeFiles = [$routesFile, $apiRoutes];
        foreach ($routeFiles as $routeFile) {
            if (!file_exists($routeFile)) continue;

            $content = file_get_contents($routeFile);
            if (!$content) continue;

            // Check for dangerous debug routes
            foreach (self::DANGEROUS_ROUTES as $dangerRoute) {
                if (str_contains($content, $dangerRoute)) {
                    $findings[] = [
                        'file'     => $routeFile,
                        'line'     => 0,
                        'pattern'  => 'debug_route',
                        'severity' => 'high',
                        'type'     => 'laravel',
                        'message'  => "Debug/Admin tool route exposed: $dangerRoute. Consider disabling in production.",
                    ];
                }
            }

            // Check for mass assignment in routes (closure-based routes with DB operations)
            if (preg_match('/Route::(get|post|put|patch|delete)\s*\([^)]*\)\s*\{[^}]*DB::/', $content)) {
                $findings[] = [
                    'file'     => $routeFile,
                    'line'     => 0,
                    'pattern'  => 'db_in_route_closure',
                    'severity' => 'medium',
                    'type'     => 'laravel',
                    'message'  => 'Direct database queries in route closures - consider using controllers',
                ];
            }

            // Check for disabled CSRF on routes
            if (preg_match('/except\s*=>\s*\[[^\]]*[\'\"][a-z\/\-]+[\'\"]/i', $content)) {
                $findings[] = [
                    'file'     => $routeFile,
                    'line'     => 0,
                    'pattern'  => 'csrf_exception',
                    'severity' => 'medium',
                    'type'     => 'laravel',
                    'message'  => 'CSRF protection is disabled for some routes in VerifyCsrfToken middleware',
                ];
            }
        }

        return $findings;
    }

    private function checkProviders(): array
    {
        $findings = [];
        $providers = $this->path . '/config/app.php';

        if (!file_exists($providers)) return $findings;

        $content = file_get_contents($providers);

        // Check for debug service providers in production
        $debugProviders = [
            'Barryvdh\\Debugbar',
            '\\Debugbar',
            '\\Telescope',
            'Ignition\\Ignition',
            '\\Clockwork',
        ];

        foreach ($debugProviders as $provider) {
            if (str_contains($content, $provider)) {
                $findings[] = [
                    'file'     => $providers,
                    'line'     => 0,
                    'pattern'  => 'debug_provider',
                    'severity' => 'medium',
                    'type'     => 'laravel',
                    'message'  => "Debug service provider ($provider) is registered. Ensure it is conditionally loaded only in local environment.",
                ];
            }
        }

        return $findings;
    }

    private function checkMiddleware(): array
    {
        $findings = [];
        $httpKernel = $this->path . '/app/Http/Kernel.php';

        if (!file_exists($httpKernel)) {
            // Laravel 11+ uses bootstrap/app.php
            $bootstrapApp = $this->path . '/bootstrap/app.php';
            if (!file_exists($bootstrapApp)) {
                $findings[] = [
                    'file'     => $this->path,
                    'line'     => 0,
                    'pattern'  => 'missing_kernel',
                    'severity' => 'info',
                    'type'     => 'laravel',
                    'message'  => 'Could not find Http Kernel or bootstrap/app.php - may be a different Laravel version structure',
                ];
            }
            return $findings;
        }

        $content = file_get_contents($httpKernel);
        if (!$content) return $findings;

        // Check if throttle middleware is configured
        if (!str_contains($content, 'throttle')) {
            $findings[] = [
                'file'     => $httpKernel,
                'line'     => 0,
                'pattern'  => 'no_throttle',
                'severity' => 'medium',
                'type'     => 'laravel',
                'message'  => 'Throttle middleware is not configured in HTTP Kernel. API rate limiting may be absent.',
            ];
        }

        // Check if 'auth' middleware is properly set
        if (str_contains($content, 'api') && !str_contains($content, 'auth:api') && !str_contains($content, 'auth:sanctum')) {
            $findings[] = [
                'file'     => $httpKernel,
                'line'     => 0,
                'pattern'  => 'api_no_auth',
                'severity' => 'high',
                'type'     => 'laravel',
                'message'  => 'API routes defined but no auth middleware configured for them',
            ];
        }

        return $findings;
    }

    private function checkStorageSymlink(): array
    {
        $findings = [];
        $symlink = $this->path . '/public/storage';

        if (!file_exists($symlink)) {
            $findings[] = [
                'file'     => $this->path,
                'line'     => 0,
                'pattern'  => 'no_storage_symlink',
                'severity' => 'low',
                'type'     => 'laravel',
                'message'  => 'No public/storage symlink. Run `php artisan storage:link` for file access.',
            ];
        }

        return $findings;
    }

    private function checkComposerPackages(): array
    {
        $findings = [];
        $composerLock = $this->path . '/composer.lock';

        if (!file_exists($composerLock)) return $findings;

        $content = file_get_contents($composerLock);
        if (!$content) return $findings;

        $lock = json_decode($content, true);
        if (!$lock || !isset($lock['packages'])) return $findings;

        // Known vulnerable packages to check (simplified - in production, use an API)
        $knownVulnerable = [];

        foreach ($lock['packages'] as $package) {
            $name = $package['name'] ?? '';
            $version = ltrim($package['version'] ?? '', 'v');

            // Check for known EOL Laravel versions
            if ($name === 'laravel/framework') {
                $eolVersions = [
                    '5.5' => '5.5', '5.6' => '5.6', '5.7' => '5.7', '5.8' => '5.8',
                    '6.0' => '6.x', '7.0' => '7.x', '8.0' => '8.x',
                    '9.0' => '9.x', '10.0' => '10.x',
                ];
                foreach ($eolVersions as $eol => $label) {
                    if (version_compare($version, $eol, '>=') && version_compare($version, $eol + 1, '<')) {
                        $findings[] = [
                            'file'     => $composerLock,
                            'line'     => 0,
                            'pattern'  => 'eol_framework',
                            'severity' => 'high',
                            'type'     => 'laravel',
                            'message'  => "Laravel $label is no longer receiving security updates. Upgrade to a supported version.",
                        ];
                    }
                }
            }

            // Check for packages known to be abandoned
            $abandoned = $package['abandoned'] ?? false;
            if ($abandoned && is_string($abandoned)) {
                $findings[] = [
                    'file'     => $composerLock,
                    'line'     => 0,
                    'pattern'  => 'abandoned_package',
                    'severity' => 'medium',
                    'type'     => 'laravel',
                    'message'  => "Package '$name' is abandoned. Replacement: $abandoned",
                ];
            } elseif ($abandoned === true) {
                $findings[] = [
                    'file'     => $composerLock,
                    'line'     => 0,
                    'pattern'  => 'abandoned_package',
                    'severity' => 'medium',
                    'type'     => 'laravel',
                    'message'  => "Package '$name' is abandoned with no replacement.",
                ];
            }
        }

        return $findings;
    }
}
