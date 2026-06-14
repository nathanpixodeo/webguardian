<?php

namespace WebGuardian\Analyzer;

class FileAnalyzer
{
    private array $options;

    private const SENSITIVE_PATTERNS = [
        '/-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/' => 'Private SSH/RSA key detected',
        '/-----BEGIN OPENSSH PRIVATE KEY-----/'          => 'OpenSSH private key detected',
        '/-----BEGIN CERTIFICATE-----/'                  => 'SSL/TLS certificate detected (public)',
        '/AKIA[0-9A-Z]{16}/'                             => 'AWS Access Key ID detected',
        '/["\'][A-Za-z0-9+\/=]{40}["\']\s*:\s*["\'][A-Za-z0-9+\/=]{40}["\']/' => 'Possible AWS secret key pair',
        '/sk_live_[0-9a-zA-Z]{24,}/'                     => 'Stripe live secret key detected',
        '/sk_test_[0-9a-zA-Z]{24,}/'                     => 'Stripe test secret key detected',
        '/ghp_[0-9a-zA-Z]{36,}/'                         => 'GitHub personal access token detected',
        '/gho_[0-9a-zA-Z]{36,}/'                         => 'GitHub OAuth access token detected',
        '/xox[bpras]-[0-9a-zA-Z\-]{24,}/'                => 'Slack API token detected',
        '/SG\.[0-9A-Za-z\-_]{22,}\.[0-9A-Za-z\-_]{43,}/' => 'SendGrid API key detected',
        '/[\'"]password[\'"]\s*=>\s*[\'"][^\'"]{0,8}[\'"]/' => 'Very short password in configuration',
    ];

    public function __construct(array $options = [])
    {
        $this->options = $options;
    }

    public function checkSensitiveContent(string $filePath): array
    {
        $findings = [];
        $content = @file_get_contents($filePath);
        if ($content === false) return $findings;

        $lines = explode("\n", $content);
        $basename = basename($filePath);

        foreach ($lines as $lineNum => $line) {
            foreach (self::SENSITIVE_PATTERNS as $pattern => $message) {
                if (preg_match($pattern, $line)) {
                    $severity = 'high';
                    // Downgrade test keys to medium
                    if (str_contains($pattern, 'sk_test') || str_contains($pattern, 'test')) {
                        $severity = 'medium';
                    }
                    // Downgrade to low for non-key files
                    if (!in_array(strtolower($basename), ['.env', '.env.example', 'wp-config.php', 'config.php',
                        'database.php', 'app.php', 'services.php', 'parameters.yml', 'secrets.yml'])) {
                        $severity = 'medium';
                    }

                    $findings[] = [
                        'file'     => $filePath,
                        'line'     => $lineNum + 1,
                        'pattern'  => 'sensitive_data',
                        'severity' => $severity,
                        'type'     => 'sensitive',
                        'message'  => $message,
                        'context'  => trim(substr($line, 0, 150)),
                    ];
                }
            }
        }

        return $findings;
    }

    public function checkPermissions(string $filePath): array
    {
        $findings = [];
        $perms = fileperms($filePath);

        // Check for world-writable files
        if ($perms & 0x0002) {
            $findings[] = [
                'file'     => $filePath,
                'line'     => 0,
                'pattern'  => 'world_writable',
                'severity' => 'high',
                'type'     => 'permission',
                'message'  => sprintf('File is world-writable (permissions: %o)', $perms & 0777),
            ];
        }

        // Check for world-readable sensitive files
        $basename = basename($filePath);
        $sensitiveNames = ['.env', 'wp-config.php', 'config.php', 'database.yml'];
        if (in_array($basename, $sensitiveNames) && ($perms & 0x0004)) {
            $findings[] = [
                'file'     => $filePath,
                'line'     => 0,
                'pattern'  => 'world_readable_config',
                'severity' => 'medium',
                'type'     => 'permission',
                'message'  => sprintf('Sensitive config file is world-readable (permissions: %o)', $perms & 0777),
            ];
        }

        return $findings;
    }
}
