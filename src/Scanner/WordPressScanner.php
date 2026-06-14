<?php

namespace WebGuardian\Scanner;

class WordPressScanner
{
    private string $path;
    private array $options;
    private array $coreHashes = [];

    private const CORE_FILES = [
        'wp-admin', 'wp-includes', 'index.php', 'wp-activate.php',
        'wp-config.php', 'wp-blog-header.php', 'wp-comments-post.php',
        'wp-cron.php', 'wp-links-opml.php', 'wp-load.php', 'wp-login.php',
        'wp-mail.php', 'wp-settings.php', 'wp-signup.php', 'wp-trackback.php',
        'xmlrpc.php', 'wp-config-sample.php',
    ];

    private const SUSPICIOUS_PLUGIN_FUNCTIONS = [
        'eval'           => 'Uses eval() - possible code injection',
        'base64_decode'  => 'Decodes base64 - often used for obfuscation',
        'exec'           => 'Executes system commands',
        'shell_exec'     => 'Executes shell commands',
        'system'         => 'Executes system commands',
        'passthru'       => 'Executes system commands with output',
        'popen'          => 'Opens process handle',
        'proc_open'      => 'Opens process for execution',
        'assert'         => 'Assert can execute code dynamically',
        'create_function'=> 'Creates anonymous function (deprecated, often abused)',
        'preg_replace'   . '/e' => 'Deprecated /e modifier allows code execution',
        'file_put_contents' => 'Writes to files - potential backdoor',
        'fwrite'         => 'Writes to files - potential backdoor',
        'chmod'          => 'Changes file permissions',
        'move_uploaded_file' => 'Uploads files',
        'curl_exec'      => 'Remote request - potential C2 callback',
        'fsockopen'      => 'Network connection - potential C2 callback',
    ];

    public function __construct(string $path, array $options = [])
    {
        $this->path = $path;
        $this->options = $options;
    }

    public function scan(): array
    {
        $findings = [];

        $findings = array_merge($findings, $this->checkVersion());
        $findings = array_merge($findings, $this->checkCoreIntegrity());
        $findings = array_merge($findings, $this->checkPluginThemes());
        $findings = array_merge($findings, $this->checkWpConfig());
        $findings = array_merge($findings, $this->checkUploads());
        $findings = array_merge($findings, $this->checkUserEnumeration());
        $findings = array_merge($findings, $this->checkDebugMode());

        return $findings;
    }

    private function checkVersion(): array
    {
        $findings = [];
        $versionFile = $this->path . '/wp-includes/version.php';

        if (!file_exists($versionFile)) {
            $findings[] = [
                'file'     => $this->path,
                'line'     => 0,
                'pattern'  => 'WordPress installation not detected or incomplete',
                'severity' => 'high',
                'type'     => 'wordpress',
                'message'  => 'Cannot verify WordPress version. Installation may be corrupted or incomplete.',
            ];
            return $findings;
        }

        $content = file_get_contents($versionFile);
        if (preg_match('/\$wp_version\s*=\s*\'([^\']+)\'/', $content, $m)) {
            $version = $m[1];
            if (version_compare($version, '5.0', '<')) {
                $findings[] = [
                    'file'     => $versionFile,
                    'line'     => 0,
                    'pattern'  => 'wp_version',
                    'severity' => 'high',
                    'type'     => 'wordpress',
                    'message'  => "Outdated WordPress version: $version. Version 5.0+ is strongly recommended.",
                ];
            }
            if (version_compare($version, '6.0', '<')) {
                $findings[] = [
                    'file'     => $versionFile,
                    'line'     => 0,
                    'pattern'  => 'wp_version',
                    'severity' => 'medium',
                    'type'     => 'wordpress',
                    'message'  => "WordPress version $version is outdated. Consider upgrading to the latest version.",
                ];
            }

            // Check for known vulnerable versions
            $vulnerable = [
                '4.7.0' => '4.7.1', '4.7.2' => '4.7.5',
                '5.0'   => '5.0.1', '5.1'   => '5.1.1',
                '5.5'   => '5.5.3', '5.6'   => '5.6.2',
                '5.7'   => '5.7.2', '5.8'   => '5.8.3',
                '5.9'   => '5.9.3', '6.0'   => '6.0.3',
                '6.1'   => '6.1.1', '6.2'   => '6.2.3',
                '6.3'   => '6.3.2', '6.4'   => '6.4.2',
                '6.5'   => '6.5.5', '6.6'   => '6.6.2',
                '6.7'   => '6.7.2',
            ];

            foreach ($vulnerable as $bad => $patch) {
                if (version_compare($version, $bad, '==')) {
                    $findings[] = [
                        'file'     => $versionFile,
                        'line'     => 0,
                        'pattern'  => "wp_version = $version",
                        'severity' => 'critical',
                        'type'     => 'wordpress',
                        'message'  => "WordPress $version has known critical vulnerabilities. Update to $patch immediately.",
                    ];
                }
            }
        }

        return $findings;
    }

    private function checkCoreIntegrity(): array
    {
        $findings = [];

        foreach (self::CORE_FILES as $coreItem) {
            $corePath = $this->path . '/' . $coreItem;
            if (!file_exists($corePath)) {
                $findings[] = [
                    'file'     => $corePath,
                    'line'     => 0,
                    'pattern'  => 'missing_core_file',
                    'severity' => 'medium',
                    'type'     => 'wordpress',
                    'message'  => "Missing WordPress core file/directory: $coreItem",
                ];
            }
        }

        // Check wp-includes for extra files (suspicious additions)
        $wpIncludes = $this->path . '/wp-includes';
        if (is_dir($wpIncludes)) {
            $expectedIncludes = ['class-wpdb.php', 'functions.php', 'plugin.php', 'theme.php',
                                  'post.php', 'user.php', 'option.php', 'general-template.php',
                                  'link-template.php', 'author-template.php', 'category-template.php',
                                  'comment-template.php', 'post-template.php', 'page-template.php',
                                  'default-constants.php', 'default-filters.php', 'default-widgets.php',
                                  'capabilities.php', 'formatting.php', 'kses.php', 'l10n.php',
                                  'locale.php', 'pluggable.php', 'pluggable-deprecated.php',
                                  'registration.php', 'rewrite.php', 'script-loader.php',
                                  'taxonomy.php', 'template-loader.php', 'vars.php', 'version.php',
                                  'cache.php', 'cron.php', 'deprecated.php', 'feed.php',
                                  'http.php', 'shortcodes.php', 'media.php', 'meta.php'];

            foreach (new \FilesystemIterator($wpIncludes, \FilesystemIterator::SKIP_DOTS) as $file) {
                if ($file->isFile() && !in_array($file->getBasename(), $expectedIncludes)) {
                    $ext = strtolower($file->getExtension());
                    if (in_array($ext, ['php', 'html', 'htm', 'phtml'])) {
                        $findings[] = [
                            'file'     => $file->getRealPath(),
                            'line'     => 0,
                            'pattern'  => 'unexpected_core_file',
                            'severity' => 'high',
                            'type'     => 'wordpress',
                            'message'  => "Unexpected file in wp-includes: {$file->getBasename()} - possible malware injection",
                        ];
                    }
                }
            }
        }

        return $findings;
    }

    private function checkPluginThemes(): array
    {
        $findings = [];

        $directories = ['wp-content/plugins', 'wp-content/themes'];
        foreach ($directories as $dir) {
            $fullPath = $this->path . '/' . $dir;
            if (!is_dir($fullPath)) continue;

            foreach (new \FilesystemIterator($fullPath, \FilesystemIterator::SKIP_DOTS) as $item) {
                if (!$item->isDir()) continue;

                $itemPath = $item->getRealPath();
                $findings = array_merge($findings, $this->scanDirectory($itemPath, $item->getBasename()));
            }
        }

        // Check mu-plugins
        $muPath = $this->path . '/wp-content/mu-plugins';
        if (is_dir($muPath)) {
            foreach (new \FilesystemIterator($muPath, \FilesystemIterator::SKIP_DOTS) as $file) {
                if ($file->isFile() && strtolower($file->getExtension()) === 'php') {
                    $content = file_get_contents($file->getRealPath());
                    if ($content && preg_match('/\b(eval|base64_decode|exec|shell_exec|system|passthru)\s*\(/', $content)) {
                        $findings[] = [
                            'file'     => $file->getRealPath(),
                            'line'     => 0,
                            'pattern'  => 'suspicious_mu_plugin',
                            'severity' => 'critical',
                            'type'     => 'wordpress',
                            'message'  => "Suspicious must-use plugin: {$file->getBasename()} contains dangerous functions",
                        ];
                    }
                }
            }
        }

        return $findings;
    }

    private function scanDirectory(string $path, string $name): array
    {
        $findings = [];

        $files = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($path, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($files as $file) {
            if (!$file->isFile()) continue;
            if (!in_array(strtolower($file->getExtension()), ['php', 'phtml', 'php5'])) continue;

            $content = @file_get_contents($file->getRealPath());
            if ($content === false) continue;

            // Check for known malware patterns specific to WordPress
            $patterns = [
                '/\bbase64_decode\s*\(\s*[\'\"][A-Za-z0-9+\/=]{100,}[\'\"]\s*\)/' => 'Obfuscated base64 payload',
                '/\$[a-z]{1,3}\s*=\s*[\'\"][A-Za-z0-9+\/=]{50,}[\'\"]\s*;\s*\$\w+\s*\.=/i' => 'Obfuscated string concatenation',
                '/\beval\s*\(\s*\$\{?\s*[\'\"]\s*<\?php/i' => 'PHP code eval injection',
                '/\b(str_rot13|gzinflate|gzuncompress|gzdecode)\s*\(\s*base64_decode/i' => 'Nested obfuscation layers',
                '/\x65\x76\x61\x6c\x28\x24\x5f\x50/' => 'Hex-encoded eval($_P',
                '/\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\s*\[[^\]]*\]\s*\{[^}]+\}/' => 'Variable variable injection from superglobal',
                '/\$\{?\s*\$_(?:GET|POST|REQUEST)\s*\[[^\]]*\]\s*\}?\s*\(/' => 'Direct callback from user input',
                '/\bassert\s*\(\s*\$_(?:GET|POST|REQUEST)/' => 'Dynamic assert with user input',
                '/preg_replace\s*\(\s*[\'\"][\/\#].*[e][\s]*[\'\"\s]/' => 'Deprecated /e modifier for preg_replace',
                '/\bcreate_function\s*\(\s*[\'\"][\'\"]\s*,\s*[\'\"]/' => 'Deprecated create_function usage',
            ];

            $lines = explode("\n", $content);
            foreach ($lines as $lineNum => $line) {
                foreach ($patterns as $pattern => $description) {
                    if (preg_match($pattern, $line)) {
                        $findings[] = [
                            'file'     => $file->getRealPath(),
                            'line'     => $lineNum + 1,
                            'pattern'  => $pattern,
                            'severity' => 'critical',
                            'type'     => 'malware',
                            'message'  => "[$name] $description",
                        ];
                    }
                }

                // Count dangerous functions
                $dangerousCount = 0;
                foreach (self::SUSPICIOUS_PLUGIN_FUNCTIONS as $func => $desc) {
                    $funcPattern = '/\b' . preg_quote($func, '/') . '\s*\(/';
                    if (preg_match($funcPattern, $line)) {
                        $dangerousCount++;
                    }
                }
                if ($dangerousCount >= 3) {
                    $findings[] = [
                        'file'     => $file->getRealPath(),
                        'line'     => $lineNum + 1,
                        'pattern'  => 'multiple_dangerous_functions',
                        'severity' => 'high',
                        'type'     => 'backdoor',
                        'message'  => "[$name] Multiple dangerous functions detected on one line ($dangerousCount)",
                    ];
                }
            }
        }

        return $findings;
    }

    private function checkWpConfig(): array
    {
        $findings = [];
        $configFile = $this->path . '/wp-config.php';

        if (!file_exists($configFile)) return $findings;

        $content = file_get_contents($configFile);

        // Debug mode enabled
        if (preg_match('/define\s*\(\s*[\'\"]WP_DEBUG[\'\"]\s*,\s*true\s*\)/i', $content)) {
            if (!preg_match('/define\s*\(\s*[\'\"]WP_DEBUG_DISPLAY[\'\"]\s*,\s*false\s*\)/i', $content)) {
                $findings[] = [
                    'file'     => $configFile,
                    'line'     => 0,
                    'pattern'  => 'WP_DEBUG',
                    'severity' => 'medium',
                    'type'     => 'wordpress',
                    'message'  => 'WP_DEBUG is enabled on a production site - may expose sensitive information',
                ];
            }
        }

        // Salts not changed
        if (preg_match('/define\s*\(\s*[\'\"]AUTH_KEY[\'\"]\s*,\s*[\'\"]put your unique phrase here[\'\"]\s*\)/i', $content)) {
            $findings[] = [
                'file'     => $configFile,
                'line'     => 0,
                'pattern'  => 'default_salts',
                'severity' => 'critical',
                'type'     => 'wordpress',
                'message'  => 'WordPress salts (AUTH_KEY, etc.) are set to default values - security keys must be unique',
            ];
        }

        // Database credentials exposed
        if (preg_match('/define\s*\(\s*[\'\"]DB_PASSWORD[\'\"]\s*,\s*[\'\"]([^\'\"]+)[\'\"]\s*\)/i', $content, $m)) {
            $password = $m[1];
            if ($password === '' || $password === 'root' || $password === 'password') {
                $findings[] = [
                    'file'     => $configFile,
                    'line'     => 0,
                    'pattern'  => 'weak_db_password',
                    'severity' => 'critical',
                    'type'     => 'wordpress',
                    'message'  => 'Database password is empty or a known default value',
                ];
            }
        }

        return $findings;
    }

    private function checkUploads(): array
    {
        $findings = [];
        $uploads = $this->path . '/wp-content/uploads';

        if (!is_dir($uploads)) return $findings;

        $files = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($uploads, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::SELF_FIRST
        );

        $executableCount = 0;
        foreach ($files as $file) {
            if (!$file->isFile()) continue;
            $ext = strtolower($file->getExtension());
            if (in_array($ext, ['php', 'phtml', 'php5', 'php7', 'pht', 'shtml', 'cgi'])) {
                $executableCount++;
                if ($executableCount <= 5) { // Only report first 5
                    $findings[] = [
                        'file'     => $file->getRealPath(),
                        'line'     => 0,
                        'pattern'  => 'executable_in_uploads',
                        'severity' => 'critical',
                        'type'     => 'wordpress',
                        'message'  => "Executable PHP file found in uploads directory: {$file->getBasename()}",
                    ];
                }
            }
        }

        if ($executableCount > 5) {
            $findings[] = [
                'file'     => $uploads,
                'line'     => 0,
                'pattern'  => 'multiple_executables_in_uploads',
                'severity' => 'critical',
                'type'     => 'wordpress',
                'message'  => "Total of $executableCount executable files found in uploads directory",
            ];
        }

        // Check for .htaccess in uploads
        $htaccess = $uploads . '/.htaccess';
        if (file_exists($htaccess)) {
            $htContent = file_get_contents($htaccess);
            if (!str_contains($htContent, 'deny from all') && !str_contains($htContent, 'Deny from all') && !str_contains($htContent, 'Require all denied')) {
                $findings[] = [
                    'file'     => $htaccess,
                    'line'     => 0,
                    'pattern'  => 'uploads_htaccess_misconfigured',
                    'severity' => 'high',
                    'type'     => 'wordpress',
                    'message'  => 'Uploads .htaccess does not deny access to PHP files',
                ];
            }
        } else {
            $findings[] = [
                'file'     => $uploads,
                'line'     => 0,
                'pattern'  => 'uploads_no_htaccess',
                'severity' => 'medium',
                'type'     => 'wordpress',
                'message'  => 'No .htaccess protection in uploads directory',
            ];
        }

        return $findings;
    }

    private function checkUserEnumeration(): array
    {
        $findings = [];

        // Check for user enumeration via REST API
        $restRoute = $this->path . '/wp-json/wp/v2/users';
        if (is_dir($this->path . '/wp-json') || is_file($this->path . '/index.php')) {
            $htaccess = $this->path . '/.htaccess';
            if (file_exists($htaccess)) {
                $content = file_get_contents($htaccess);
                if (!str_contains($content, 'wp-json/wp/v2/users') && !str_contains($content, 'rest_user')) {
                    $findings[] = [
                        'file'     => $htaccess,
                        'line'     => 0,
                        'pattern'  => 'user_enumeration',
                        'severity' => 'low',
                        'type'     => 'wordpress',
                        'message'  => 'User enumeration via REST API (/wp/v2/users) is not blocked',
                    ];
                }
            }
        }

        return $findings;
    }

    private function checkDebugMode(): array
    {
        $findings = [];

        // Check if debug log is exposed
        $debugLog = $this->path . '/wp-content/debug.log';
        if (file_exists($debugLog)) {
            $size = filesize($debugLog);
            if ($size > 0) {
                $findings[] = [
                    'file'     => $debugLog,
                    'line'     => 0,
                    'pattern'  => 'debug_log_exposed',
                    'severity' => 'high',
                    'type'     => 'wordpress',
                    'message'  => "WordPress debug.log exists and is accessible ($size bytes) - may contain sensitive debugging information",
                ];
            }
        }

        return $findings;
    }
}
