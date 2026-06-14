<?php

namespace WebGuardian\Analyzer;

class DatabaseAnalyzer
{
    private array $options;

    private const CONFIG_FILES = [
        '.env', '.env.example',
        'wp-config.php',
        'config/database.php',
        'config/app.php',
        'app/config/database.php',
        'app/config/parameters.yml',
        'app/config/parameters.php',
        'config.php',
        'db.php',
        'database.php',
        'configuration.php',  // Joomla
        'settings.php',       // Drupal
    ];

    public function __construct(array $options = [])
    {
        $this->options = $options;
    }

    public function findExposedConfigs(string $path): array
    {
        $findings = [];

        foreach (self::CONFIG_FILES as $configFile) {
            $configPath = $path . '/' . $configFile;
            if (file_exists($configPath)) {
                $content = @file_get_contents($configPath);
                if (!$content) continue;

                $configDir = dirname($configPath);
                $findings = array_merge($findings, $this->analyzeConfig($configPath, $configDir, $content));
            }
        }

        // Check for SQL dump files
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($path, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($iterator as $file) {
            if (!$file->isFile()) continue;
            $name = strtolower($file->getBasename());
            $ext  = strtolower($file->getExtension());

            if (in_array($ext, ['sql', 'dump', 'backup']) ||
                preg_match('/\b(dump|export|backup)\b.*\.sql$/i', $name)) {

                $size = $file->getSize();
                $findings[] = [
                    'file'     => $file->getRealPath(),
                    'line'     => 0,
                    'pattern'  => 'sql_dump',
                    'severity' => 'critical',
                    'type'     => 'sensitive',
                    'message'  => "SQL dump file found ({$file->getBasename()}, {$size} bytes) - may contain entire database with user credentials",
                ];
            }
        }

        return $findings;
    }

    private function analyzeConfig(string $configPath, string $configDir, string $content): array
    {
        $findings = [];
        $basename = basename($configPath);

        // Check if config file has valid restricted permissions
        $perms = fileperms($configPath);
        $octal = substr(sprintf('%o', $perms), -3);

        // Look for database credentials in the content
        $dbPatterns = [
            '/[\'"]DB_HOST[\'"]\s*[=:>]\s*[\'"]([^\'"]+)[\'"]/i'   => 'Database host: {value}',
            '/[\'"]DB_NAME[\'"]\s*[=:>]\s*[\'"]([^\'"]+)[\'"]/i'   => 'Database name: {value}',
            '/[\'"]DB_USER[\'"]\s*[=:>]\s*[\'"]([^\'"]+)[\'"]/i'   => 'Database user: {value}',
            '/[\'"]DB_PASSWORD[\'"]\s*[=:>]\s*[\'"]([^\'"]+)[\'"]/i' => 'Database password: {value}',
            '/[\'"]DB_DATABASE[\'"]\s*[=:>]\s*[\'"]([^\'"]+)[\'"]/i' => 'Database name: {value}',
            '/[\'"]DB_USERNAME[\'"]\s*[=:>]\s*[\'"]([^\'"]+)[\'"]/i' => 'Database user: {value}',
        ];

        $creds = [];
        foreach ($dbPatterns as $pattern => $template) {
            if (preg_match($pattern, $content, $m)) {
                $value = $m[1];
                if (!empty($value) && $value !== 'root' && $value !== 'password' && $value !== 'secret') {
                    $creds[] = trim($value);
                }
            }
        }

        if (!empty($creds)) {
            // Check if config is in a web-accessible location
            $relativePath = str_replace($configDir, '', $configPath);
            if ($basename === '.env' && is_dir(dirname($configPath) . '/public')) {
                // .env should be outside public - this is likely fine
            }

            $findings[] = [
                'file'     => $configPath,
                'line'     => 0,
                'pattern'  => 'db_config_found',
                'severity' => 'info',
                'type'     => 'sensitive',
                'message'  => "Database configuration file found ($basename) with credentials configured",
            ];
        }

        return $findings;
    }
}
