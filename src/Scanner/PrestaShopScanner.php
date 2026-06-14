<?php

namespace WebGuardian\Scanner;

class PrestaShopScanner
{
    private string $path;
    private array $options;

    private const KNOWN_VERSIONS = [
        '1.4.0.1'  => ['eol' => '2012', 'critical' => true],
        '1.4.0.2'  => ['eol' => '2012', 'critical' => true],
        '1.4.0.3'  => ['eol' => '2012', 'critical' => true],
        '1.4.1.0'  => ['eol' => '2012', 'critical' => true],
        '1.4.2.0'  => ['eol' => '2012', 'critical' => true],
        '1.4.3.0'  => ['eol' => '2012', 'critical' => true],
        '1.4.4.0'  => ['eol' => '2012', 'critical' => true],
        '1.4.4.1'  => ['eol' => '2012', 'critical' => true],
        '1.4.5.0'  => ['eol' => '2013', 'critical' => true],
        '1.4.5.1'  => ['eol' => '2013', 'critical' => true],
        '1.4.6.0'  => ['eol' => '2013', 'critical' => true],
        '1.4.6.1'  => ['eol' => '2013', 'critical' => true],
        '1.4.6.2'  => ['eol' => '2013', 'critical' => true],
        '1.4.7.0'  => ['eol' => '2013', 'critical' => true],
        '1.4.7.1'  => ['eol' => '2013', 'critical' => true],
        '1.4.7.2'  => ['eol' => '2013', 'critical' => true],
        '1.4.7.3'  => ['eol' => '2013', 'critical' => true],
        '1.4.8.0'  => ['eol' => '2013', 'critical' => true],
        '1.4.8.1'  => ['eol' => '2013', 'critical' => true],
        '1.4.8.2'  => ['eol' => '2013', 'critical' => true],
        '1.4.8.3'  => ['eol' => '2013', 'critical' => true],
        '1.4.9.0'  => ['eol' => '2014', 'critical' => true],
        '1.4.10.0' => ['eol' => '2014', 'critical' => true],
        '1.4.11.0' => ['eol' => '2014', 'critical' => true],
        '1.4.11.1' => ['eol' => '2014', 'critical' => true],
        '1.5.0.0'  => ['eol' => '2015', 'critical' => true],
        '1.5.0.1'  => ['eol' => '2015', 'critical' => true],
        '1.5.0.2'  => ['eol' => '2015', 'critical' => true],
        '1.5.0.3'  => ['eol' => '2015', 'critical' => true],
        '1.5.1.0'  => ['eol' => '2015', 'critical' => true],
        '1.5.2.0'  => ['eol' => '2015', 'critical' => true],
        '1.5.3.0'  => ['eol' => '2015', 'critical' => true],
        '1.5.3.1'  => ['eol' => '2015', 'critical' => true],
        '1.5.4.0'  => ['eol' => '2015', 'critical' => true],
        '1.5.4.1'  => ['eol' => '2015', 'critical' => true],
        '1.5.5.0'  => ['eol' => '2016', 'critical' => true],
        '1.5.6.0'  => ['eol' => '2016', 'critical' => true],
        '1.5.6.1'  => ['eol' => '2016', 'critical' => true],
        '1.5.6.2'  => ['eol' => '2016', 'critical' => true],
        '1.5.6.3'  => ['eol' => '2016', 'critical' => true],
        '1.6.0.0'  => ['eol' => '2016', 'critical' => true],
        '1.6.0.1'  => ['eol' => '2016', 'critical' => true],
        '1.6.0.2'  => ['eol' => '2016', 'critical' => true],
        '1.6.0.3'  => ['eol' => '2016', 'critical' => true],
        '1.6.0.4'  => ['eol' => '2016', 'critical' => true],
        '1.6.0.5'  => ['eol' => '2016', 'critical' => true],
        '1.6.0.6'  => ['eol' => '2016', 'critical' => true],
        '1.6.0.7'  => ['eol' => '2016', 'critical' => true],
        '1.6.0.8'  => ['eol' => '2016', 'critical' => true],
        '1.6.0.9'  => ['eol' => '2016', 'critical' => true],
        '1.6.0.10' => ['eol' => '2016', 'critical' => true],
        '1.6.0.11' => ['eol' => '2016', 'critical' => true],
        '1.6.0.12' => ['eol' => '2016', 'critical' => true],
        '1.6.0.13' => ['eol' => '2016', 'critical' => true],
        '1.6.0.14' => ['eol' => '2016', 'critical' => true],
        '1.6.1.0'  => ['eol' => '2019', 'critical' => true],
        '1.6.1.1'  => ['eol' => '2019', 'critical' => true],
        '1.6.1.2'  => ['eol' => '2019', 'critical' => true],
        '1.6.1.3'  => ['eol' => '2019', 'critical' => true],
        '1.6.1.4'  => ['eol' => '2019', 'critical' => true],
        '1.6.1.5'  => ['eol' => '2019', 'critical' => true],
        '1.6.1.6'  => ['eol' => '2019', 'critical' => true],
        '1.6.1.7'  => ['eol' => '2019', 'critical' => true],
        '1.6.1.8'  => ['eol' => '2019', 'critical' => true],
        '1.6.1.9'  => ['eol' => '2019', 'critical' => true],
        '1.6.1.10' => ['eol' => '2019', 'critical' => true],
        '1.6.1.11' => ['eol' => '2019', 'critical' => true],
        '1.6.1.12' => ['eol' => '2019', 'critical' => true],
        '1.6.1.13' => ['eol' => '2019', 'critical' => true],
        '1.6.1.14' => ['eol' => '2019', 'critical' => true],
        '1.6.1.15' => ['eol' => '2019', 'critical' => true],
        '1.6.1.16' => ['eol' => '2019', 'critical' => true],
        '1.6.1.17' => ['eol' => '2019', 'critical' => true],
        '1.6.1.18' => ['eol' => '2019', 'critical' => true],
        '1.6.1.19' => ['eol' => '2019', 'critical' => true],
        '1.6.1.20' => ['eol' => '2019', 'critical' => true],
        '1.6.1.21' => ['eol' => '2019', 'critical' => true],
        '1.6.1.22' => ['eol' => '2020', 'critical' => true],
        '1.6.1.23' => ['eol' => '2020', 'critical' => true],
        '1.6.1.24' => ['eol' => '2021', 'critical' => true],
        '1.7.0.0'  => ['eol' => '2017', 'critical' => true],
        '1.7.0.1'  => ['eol' => '2017', 'critical' => true],
        '1.7.0.2'  => ['eol' => '2017', 'critical' => true],
        '1.7.0.3'  => ['eol' => '2017', 'critical' => true],
        '1.7.0.4'  => ['eol' => '2017', 'critical' => true],
        '1.7.0.5'  => ['eol' => '2018', 'critical' => true],
        '1.7.0.6'  => ['eol' => '2018', 'critical' => true],
        '1.7.1.0'  => ['eol' => '2018', 'critical' => true],
        '1.7.1.1'  => ['eol' => '2018', 'critical' => true],
        '1.7.1.2'  => ['eol' => '2018', 'critical' => true],
        '1.7.2.0'  => ['eol' => '2018', 'critical' => true],
        '1.7.2.1'  => ['eol' => '2018', 'critical' => true],
        '1.7.2.2'  => ['eol' => '2018', 'critical' => true],
        '1.7.2.3'  => ['eol' => '2018', 'critical' => true],
        '1.7.2.4'  => ['eol' => '2018', 'critical' => true],
        '1.7.3.0'  => ['eol' => '2019', 'critical' => true],
        '1.7.3.1'  => ['eol' => '2019', 'critical' => true],
        '1.7.3.2'  => ['eol' => '2019', 'critical' => true],
        '1.7.3.3'  => ['eol' => '2019', 'critical' => true],
        '1.7.3.4'  => ['eol' => '2019', 'critical' => true],
        '1.7.4.0'  => ['eol' => '2019', 'critical' => true],
        '1.7.4.1'  => ['eol' => '2019', 'critical' => true],
        '1.7.4.2'  => ['eol' => '2019', 'critical' => true],
        '1.7.4.3'  => ['eol' => '2019', 'critical' => true],
        '1.7.4.4'  => ['eol' => '2019', 'critical' => true],
        '1.7.5.0'  => ['eol' => '2020', 'critical' => true],
        '1.7.5.1'  => ['eol' => '2020', 'critical' => true],
        '1.7.5.2'  => ['eol' => '2020', 'critical' => true],
        '1.7.6.0'  => ['eol' => '2020', 'critical' => true],
        '1.7.6.1'  => ['eol' => '2020', 'critical' => true],
        '1.7.6.2'  => ['eol' => '2020', 'critical' => true],
        '1.7.6.3'  => ['eol' => '2020', 'critical' => true],
        '1.7.6.4'  => ['eol' => '2020', 'critical' => true],
        '1.7.6.5'  => ['eol' => '2021', 'critical' => true],
        '1.7.6.6'  => ['eol' => '2021', 'critical' => true],
        '1.7.6.7'  => ['eol' => '2021', 'critical' => true],
        '1.7.6.8'  => ['eol' => '2021', 'critical' => true],
        '1.7.6.9'  => ['eol' => '2021', 'critical' => true],
        '1.7.7.0'  => ['eol' => '2021', 'critical' => true],
        '1.7.7.1'  => ['eol' => '2021', 'critical' => true],
        '1.7.7.2'  => ['eol' => '2021', 'critical' => true],
        '1.7.7.3'  => ['eol' => '2021', 'critical' => true],
        '1.7.7.4'  => ['eol' => '2021', 'critical' => true],
        '1.7.7.5'  => ['eol' => '2022', 'critical' => true],
        '1.7.7.6'  => ['eol' => '2022', 'critical' => true],
        '1.7.7.7'  => ['eol' => '2022', 'critical' => true],
        '1.7.7.8'  => ['eol' => '2022', 'critical' => true],
        '1.7.8.0'  => ['eol' => '2022', 'critical' => true],
        '1.7.8.1'  => ['eol' => '2022', 'critical' => true],
        '1.7.8.2'  => ['eol' => '2022', 'critical' => true],
        '1.7.8.3'  => ['eol' => '2022', 'critical' => true],
        '1.7.8.4'  => ['eol' => '2022', 'critical' => true],
        '1.7.8.5'  => ['eol' => '2022', 'critical' => true],
        '1.7.8.6'  => ['eol' => '2022', 'critical' => true],
        '1.7.8.7'  => ['eol' => '2023', 'critical' => true],
        '1.7.8.8'  => ['eol' => '2023', 'critical' => true],
        '1.7.8.9'  => ['eol' => '2023', 'critical' => true],
        '1.7.8.10' => ['eol' => '2023', 'critical' => true],
        '8.0.0'    => ['eol' => '2024', 'critical' => false],
        '8.0.1'    => ['eol' => '2024', 'critical' => false],
        '8.0.2'    => ['eol' => '2024', 'critical' => false],
        '8.0.3'    => ['eol' => '2024', 'critical' => false],
        '8.0.4'    => ['eol' => '2024', 'critical' => false],
        '8.0.5'    => ['eol' => '2025', 'critical' => false],
        '8.1.0'    => ['eol' => '2025', 'critical' => false],
        '8.1.1'    => ['eol' => '2025', 'critical' => false],
        '8.1.2'    => ['eol' => '2025', 'critical' => false],
        '8.1.3'    => ['eol' => '2025', 'critical' => false],
        '8.1.4'    => ['eol' => '2025', 'critical' => false],
        '8.1.5'    => ['eol' => '2025', 'critical' => false],
        '8.1.6'    => ['eol' => '2025', 'critical' => false],
        '8.2.0'    => ['eol' => '2026', 'critical' => false],
    ];

    private const EOL_MAJOR = [
        '1.4' => ['label' => '1.4.x', 'year' => '2014', 'critical' => true],
        '1.5' => ['label' => '1.5.x', 'year' => '2016', 'critical' => true],
        '1.6' => ['label' => '1.6.x', 'year' => '2021', 'critical' => true],
        '1.7' => ['label' => '1.7.x', 'year' => '2023', 'critical' => true],
        '8.0' => ['label' => '8.0.x', 'year' => '2024', 'critical' => false],
        '8.1' => ['label' => '8.1.x', 'year' => '2025', 'critical' => false],
        '8.2' => ['label' => '8.2.x', 'year' => '2026', 'critical' => false],
    ];

    private const SENSITIVE_DIRS = [
        '/install',
        '/install.php',
        '/admin',
        '/app/config',
        '/config',
        '/cache',
        '/log',
        '/logs',
        '/upload',
        '/download',
        '/img',
        '/pdf',
        '/override',
        '/modules',
        '/themes',
        '/var/log',
        '/var/cache',
    ];

    private const NOT_ALLOWED_IN_UPLOAD = ['php', 'phtml', 'php5', 'php7', 'pht', 'cgi', 'exe', 'sh'];

    public function __construct(string $path, array $options = [])
    {
        $this->path = $path;
        $this->options = $options;
    }

    public function scan(): array
    {
        $findings = [];

        $findings = array_merge($findings, $this->checkVersion());
        $findings = array_merge($findings, $this->checkInstallDir());
        $findings = array_merge($findings, $this->checkConfigFiles());
        $findings = array_merge($findings, $this->checkAdminDirectory());
        $findings = array_merge($findings, $this->checkModules());
        $findings = array_merge($findings, $this->checkOverrides());
        $findings = array_merge($findings, $this->checkUploadDirs());
        $findings = array_merge($findings, $this->checkHtaccess());
        $findings = array_merge($findings, $this->checkSslConfig());
        $findings = array_merge($findings, $this->checkBackdoorFiles());
        $findings = array_merge($findings, $this->checkKnownInfectedFiles());
        $findings = array_merge($findings, $this->checkThemeSkimmers());
        $findings = array_merge($findings, $this->checkAdminEvasion());
        $findings = array_merge($findings, $this->checkPhpUnitVulns());

        return $findings;
    }

    private function checkVersion(): array
    {
        $findings = [];

        // PrestaShop 1.7+ uses version file in app/
        $versionPaths = [
            $this->path . '/app/AppKernel.php',
            $this->path . '/config/settings.inc.php',
            $this->path . '/classes/Shop.php',
            $this->path . '/install-dev/install_version.php',
            $this->path . '/install/install_version.php',
        ];

        $version = null;
        $versionSource = null;

        foreach ($versionPaths as $vp) {
            if (!file_exists($vp)) continue;

            $content = file_get_contents($vp);
            if (!$content) continue;

            // PrestaShop 1.7+: _PS_VERSION_ constant
            if (preg_match('/_PS_VERSION_\s*=\s*[\'"](\d+\.\d+\.\d+)[\'"]/', $content, $m)) {
                $version = $m[1];
                $versionSource = $vp;
                break;
            }
            // PrestaShop 1.6.x: PS_VERSION constant
            if (preg_match('/define\s*\(\s*[\'"]_PS_VERSION_[\'"]\s*,\s*[\'"](\d+\.\d+\.\d+)[\'"]/', $content, $m)) {
                $version = $m[1];
                $versionSource = $vp;
                break;
            }
        }

        // Fallback: try composer.json
        if (!$version) {
            $composerPath = $this->path . '/composer.json';
            if (file_exists($composerPath)) {
                $content = file_get_contents($composerPath);
                if ($content) {
                    $data = json_decode($content, true);
                    if ($data && isset($data['extra']['prestashop']['version'])) {
                        $version = $data['extra']['prestashop']['version'];
                        $versionSource = $composerPath;
                    }
                }
            }
        }

        if (!$version) {
            $findings[] = [
                'file'     => $this->path,
                'line'     => 0,
                'pattern'  => 'ps_unknown_version',
                'severity' => 'medium',
                'type'     => 'prestashop',
                'message'  => 'Cannot determine PrestaShop version. May be heavily customized or corrupted.',
            ];
            return $findings;
        }

        $major = substr($version, 0, strrpos($version, '.') ?: 3);
        $majorShort = substr($version, 0, 3);

        // Check exact version in known list
        if (isset(self::KNOWN_VERSIONS[$version])) {
            $info = self::KNOWN_VERSIONS[$version];
            if ($info['critical']) {
                $severity = 'critical';
                $msg = "PrestaShop $version reached End-of-Life in {$info['eol']}. No security patches available. Upgrade immediately.";
            } else {
                $severity = 'high';
                $msg = "PrestaShop $version is outdated (EOL {$info['eol']}). Consider upgrading to a supported version.";
            }
            if ($info['critical'] && version_compare($version, '1.7', '<')) {
                $severity = 'critical';
                $msg = "PrestaShop $version is critically outdated (EOL {$info['eol']}). Multiple known CVEs unpatched.";
            }
            $findings[] = [
                'file'     => $versionSource,
                'line'     => 0,
                'pattern'  => 'ps_outdated_version',
                'severity' => $severity,
                'type'     => 'prestashop',
                'message'  => $msg,
            ];
        } else {
            // Check by major version EOL
            foreach (self::EOL_MAJOR as $prefix => $info) {
                if (str_starts_with($version, $prefix . '.') || $version === $prefix) {
                    if ($info['critical']) {
                        $findings[] = [
                            'file'     => $versionSource,
                            'line'     => 0,
                            'pattern'  => 'ps_eol_major',
                            'severity' => 'critical',
                            'type'     => 'prestashop',
                            'message'  => "PrestaShop {$info['label']} reached End-of-Life in {$info['year']}. Version $version is no longer supported.",
                        ];
                    } else {
                        // Check if EOL is approaching
                        $eolYear = (int)$info['year'];
                        $currentYear = (int)date('Y');
                        if ($currentYear >= $eolYear) {
                            $findings[] = [
                                'file'     => $versionSource,
                                'line'     => 0,
                                'pattern'  => 'ps_nearing_eol',
                                'severity' => 'medium',
                                'type'     => 'prestashop',
                                'message'  => "PrestaShop {$info['label']} reached End-of-Life in {$info['year']}. Consider upgrading.",
                            ];
                        } else {
                            $findings[] = [
                                'file'     => $versionSource,
                                'line'     => 0,
                                'pattern'  => 'ps_version_info',
                                'severity' => 'info',
                                'type'     => 'prestashop',
                                'message'  => "PrestaShop $version detected (EOL: {$info['label']} in {$info['year']}).",
                            ];
                        }
                    }
                    break;
                }
            }
        }

        return $findings;
    }

    private function checkInstallDir(): array
    {
        $findings = [];

        $installDirs = [
            $this->path . '/install',
            $this->path . '/install-dev',
        ];

        foreach ($installDirs as $dir) {
            if (is_dir($dir)) {
                $findings[] = [
                    'file'     => $dir,
                    'line'     => 0,
                    'pattern'  => 'ps_install_dir_exists',
                    'severity' => 'critical',
                    'type'     => 'prestashop',
                    'message'  => "Installation directory still exists: " . basename($dir) . ". Attackers can reinstall and take over the shop.",
                ];
            }
        }

        $installPhpOld = [
            $this->path . '/install.php.bak',
            $this->path . '/install.php.old',
            $this->path . '/install.php.save',
        ];
        foreach ($installPhpOld as $f) {
            if (file_exists($f)) {
                $findings[] = [
                    'file'     => $f,
                    'line'     => 0,
                    'pattern'  => 'ps_install_backup',
                    'severity' => 'high',
                    'type'     => 'prestashop',
                    'message'  => "Backup of install script found: " . basename($f) . ". Remove if not needed.",
                ];
            }
        }

        return $findings;
    }

    private function checkConfigFiles(): array
    {
        $findings = [];

        // PrestaShop 1.6.x: config/settings.inc.php
        $settingsFile = $this->path . '/config/settings.inc.php';
        if (file_exists($settingsFile)) {
            $content = file_get_contents($settingsFile);
            if ($content) {
                // Check database credentials
                if (preg_match('/_DB_PASSWD_\s*=\s*[\'"](\S+)[\'"]/', $content, $m)) {
                    $pass = $m[1];
                    if ($pass === '' || $pass === 'root' || $pass === 'password' || $pass === '123456' || $pass === 'admin') {
                        $findings[] = [
                            'file'     => $settingsFile,
                            'line'     => 0,
                            'pattern'  => 'ps_weak_db_password',
                            'severity' => 'critical',
                            'type'     => 'prestashop',
                            'message'  => "Database password in settings.inc.php is weak or default: '$pass'",
                        ];
                    }
                }

                // Check cookie key (PrestaShop 1.6)
                if (preg_match('/_COOKIE_KEY_\s*=\s*[\'"](\S+)[\'"]/', $content, $m)) {
                    $key = $m[1];
                    if (strlen($key) < 16) {
                        $findings[] = [
                            'file'     => $settingsFile,
                            'line'     => 0,
                            'pattern'  => 'ps_weak_cookie_key',
                            'severity' => 'critical',
                            'type'     => 'prestashop',
                            'message'  => "Cookie key is too short (" . strlen($key) . " chars). Security is compromised.",
                        ];
                    }
                }

                // Check file permissions setting
                if (preg_match('/_PS_MODE_DEV_\s*,\s*true/i', $content)) {
                    $findings[] = [
                        'file'     => $settingsFile,
                        'line'     => 0,
                        'pattern'  => 'ps_dev_mode',
                        'severity' => 'high',
                        'type'     => 'prestashop',
                        'message'  => "PrestaShop is in Development Mode (_PS_MODE_DEV_). Error details exposed to users.",
                    ];
                }

                // Check permissions
                $perms = fileperms($settingsFile);
                if ($perms & 0x0004) {
                    $findings[] = [
                        'file'     => $settingsFile,
                        'line'     => 0,
                        'pattern'  => 'ps_config_world_readable',
                        'severity' => 'high',
                        'type'     => 'prestashop',
                        'message'  => "settings.inc.php is world-readable (permissions: " . substr(sprintf('%o', $perms), -3) . "). Database credentials exposed.",
                    ];
                }
            }
        }

        // PrestaShop 1.7+ uses Symfony config: app/config/parameters.php
        $symfonyConfigs = [
            $this->path . '/app/config/parameters.php',
            $this->path . '/app/config/parameters.yml',
        ];
        foreach ($symfonyConfigs as $sc) {
            if (file_exists($sc)) {
                $perms = fileperms($sc);
                if ($perms & 0x0004) {
                    $findings[] = [
                        'file'     => $sc,
                        'line'     => 0,
                        'pattern'  => 'ps_parameters_world_readable',
                        'severity' => 'high',
                        'type'     => 'prestashop',
                        'message'  => basename($sc) . " is world-readable. Contains database and secret keys.",
                    ];
                }
            }
        }

        // Check for .env file in PrestaShop 8.x
        $envFile = $this->path . '/.env';
        if (file_exists($envFile)) {
            $publicEnv = $this->path . '/public/.env';
            if (file_exists($publicEnv)) {
                $findings[] = [
                    'file'     => $publicEnv,
                    'line'     => 0,
                    'pattern'  => 'ps_env_in_public',
                    'severity' => 'critical',
                    'type'     => 'prestashop',
                    'message'  => '.env file found in public directory - credentials exposed to web.',
                ];
            }
        }

        return $findings;
    }

    private function checkAdminDirectory(): array
    {
        $findings = [];

        // PrestaShop admin dir is usually renamed. Find it.
        $adminDir = null;
        $iterator = new \FilesystemIterator($this->path, \FilesystemIterator::SKIP_DOTS);
        foreach ($iterator as $file) {
            if ($file->isDir() && preg_match('/^admin/', $file->getBasename())) {
                $adminDir = $file->getRealPath();
                break;
            }
        }

        if (!$adminDir) {
            // Try common names
            foreach (['admin', 'admin-dev', 'administration', 'backoffice', 'staff'] as $name) {
                $testPath = $this->path . '/' . $name;
                if (is_dir($testPath)) {
                    $adminDir = $testPath;
                    break;
                }
            }
        }

        if ($adminDir) {
            $adminName = basename($adminDir);

            if ($adminName === 'admin' || $adminName === 'admin-dev') {
                $findings[] = [
                    'file'     => $adminDir,
                    'line'     => 0,
                    'pattern'  => 'ps_default_admin',
                    'severity' => 'high',
                    'type'     => 'prestashop',
                    'message'  => "Admin directory uses default name '$adminName'. Rename it to prevent brute-force attacks.",
                ];
            }

            // Check admin .htaccess
            $adminHtaccess = $adminDir . '/.htaccess';
            if (file_exists($adminHtaccess)) {
                $htContent = file_get_contents($adminHtaccess);
                if ($htContent && !str_contains($htContent, 'Require all denied') &&
                    !str_contains($htContent, 'Deny from all') &&
                    !str_contains($htContent, 'Allow from')) {
                    $findings[] = [
                        'file'     => $adminHtaccess,
                        'line'     => 0,
                        'pattern'  => 'ps_admin_no_ip_restriction',
                        'severity' => 'medium',
                        'type'     => 'prestashop',
                        'message'  => "Admin .htaccess has no IP restriction. Consider restricting admin access by IP.",
                    ];
                }
            } else {
                $findings[] = [
                    'file'     => $adminDir,
                    'line'     => 0,
                    'pattern'  => 'ps_admin_no_htaccess',
                    'severity' => 'medium',
                    'type'     => 'prestashop',
                    'message'  => "Admin directory has no .htaccess protection.",
                ];
            }

            // Check for world-readable admin files
            $adminIndex = $adminDir . '/index.php';
            if (file_exists($adminIndex)) {
                $perms = fileperms($adminIndex);
                if ($perms & 0x0002) {
                    $findings[] = [
                        'file'     => $adminIndex,
                        'line'     => 0,
                        'pattern'  => 'ps_admin_world_writable',
                        'severity' => 'high',
                        'type'     => 'prestashop',
                        'message'  => "Admin index.php is world-writable. Possible defacement or backdoor.",
                    ];
                }
            }

            // Check for random files in admin
            $adminFiles = new \FilesystemIterator($adminDir, \FilesystemIterator::SKIP_DOTS);
            $adminFileCount = iterator_count($adminFiles);
            if ($adminFileCount > 200) {
                $findings[] = [
                    'file'     => $adminDir,
                    'line'     => 0,
                    'pattern'  => 'ps_admin_large',
                    'severity' => 'low',
                    'type'     => 'prestashop',
                    'message'  => "Admin directory has $adminFileCount files. Large admin may indicate bloat or compromise.",
                ];
            }
        } else {
            $findings[] = [
                'file'     => $this->path,
                'line'     => 0,
                'pattern'  => 'ps_no_admin',
                'severity' => 'info',
                'type'     => 'prestashop',
                'message'  => 'No admin directory found. May use a custom admin path.',
            ];
        }

        return $findings;
    }

    private function checkModules(): array
    {
        $findings = [];
        $modulesDir = $this->path . '/modules';

        if (!is_dir($modulesDir)) return $findings;

        // Scan each module
        $moduleDirs = new \FilesystemIterator($modulesDir, \FilesystemIterator::SKIP_DOTS);
        $totalModules = 0;
        $disabledModules = 0;
        $suspiciousModules = [];

        foreach ($moduleDirs as $module) {
            if (!$module->isDir()) continue;
            $totalModules++;

            $moduleName = $module->getBasename();
            $modulePath = $module->getRealPath();

            // Skip standard/known modules
            if ($this->isCoreModule($moduleName)) continue;

            // Check for suspicious module names
            if (preg_match('/^(?:shell|cmd|eval|backdoor|uploader|connector|\d{10,})$/i', $moduleName)) {
                $suspiciousModules[] = $moduleName;
                $findings[] = [
                    'file'     => $modulePath,
                    'line'     => 0,
                    'pattern'  => 'ps_suspicious_module_name',
                    'severity' => 'critical',
                    'type'     => 'prestashop',
                    'message'  => "Suspicious module name: '$moduleName'. Possible backdoor.",
                ];
                continue;
            }

            // Check if module has an index.php with dangerous content
            $moduleIndex = $modulePath . '/index.php';
            $moduleMain = $modulePath . '/' . $moduleName . '.php';

            $filesToCheck = [$moduleIndex, $moduleMain];
            foreach ($filesToCheck as $mf) {
                if (!file_exists($mf)) continue;
                $content = @file_get_contents($mf);
                if (!$content) continue;

                // Look for eval, base64, system etc in module files
                if (preg_match('/\b(eval|base64_decode|exec|shell_exec|system|passthru|popen|proc_open)\s*\(/', $content)) {
                    // But skip if it's legitimately part of the module's functionality
                    if ($this->isLikelyMalicious($content, $moduleName)) {
                        $findings[] = [
                            'file'     => $mf,
                            'line'     => 0,
                            'pattern'  => 'ps_module_dangerous_func',
                            'severity' => 'high',
                            'type'     => 'prestashop',
                            'message'  => "Module '$moduleName' contains dangerous functions in " . basename($mf),
                        ];
                    }
                }
            }

            // Check for obfuscated files in module
            $moduleFiles = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($modulePath, \FilesystemIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::SELF_FIRST
            );
            foreach ($moduleFiles as $mf) {
                if (!$mf->isFile()) continue;
                $ext = strtolower($mf->getExtension());
                if (!in_array($ext, ['php', 'phtml', 'php5', 'tpl'])) continue;
                if ($mf->getSize() > 500000) continue; // Skip large files

                $content = @file_get_contents($mf->getRealPath());
                if (!$content) continue;

                if (preg_match('/\beval\s*\(\s*base64_decode\s*\(/i', $content)) {
                    $findings[] = [
                        'file'     => $mf->getRealPath(),
                        'line'     => 0,
                        'pattern'  => 'ps_module_obfuscated',
                        'severity' => 'critical',
                        'type'     => 'prestashop',
                        'message'  => "Obfuscated code found in module '$moduleName': " . $mf->getBasename(),
                    ];
                }
            }
        }

        $findings[] = [
            'file'     => $modulesDir,
            'line'     => 0,
            'pattern'  => 'ps_module_count',
            'severity' => 'info',
            'type'     => 'prestashop',
            'message'  => "PrestaShop has $totalModules module(s) installed.",
        ];

        return $findings;
    }

    private function checkOverrides(): array
    {
        $findings = [];
        $overrideDir = $this->path . '/override';

        if (!is_dir($overrideDir)) return $findings;

        $overrideFiles = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($overrideDir, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::SELF_FIRST
        );

        $overrideCount = 0;
        foreach ($overrideFiles as $file) {
            if (!$file->isFile()) continue;
            $overrideCount++;

            if ($overrideCount <= 10) {
                $content = @file_get_contents($file->getRealPath());
                if ($content && preg_match('/\b(eval|base64_decode|exec|system|file_put_contents)\s*\(/', $content)) {
                    $findings[] = [
                        'file'     => $file->getRealPath(),
                        'line'     => 0,
                        'pattern'  => 'ps_override_dangerous',
                        'severity' => 'high',
                        'type'     => 'prestashop',
                        'message'  => "Override file contains suspicious functions: " . basename($file->getRealPath()),
                    ];
                }
            }
        }

        if ($overrideCount > 10) {
            $findings[] = [
                'file'     => $overrideDir,
                'line'     => 0,
                'pattern'  => 'ps_many_overrides',
                'severity' => 'medium',
                'type'     => 'prestashop',
                'message'  => "Large number of overrides ($overrideCount). Each override increases maintenance and security risk.",
            ];
        }

        return $findings;
    }

    private function checkUploadDirs(): array
    {
        $findings = [];

        $sensitiveDirs = [
            'upload'   => $this->path . '/upload',
            'download' => $this->path . '/download',
            'img'      => $this->path . '/img',
            'pdf'      => $this->path . '/pdf',
        ];

        foreach ($sensitiveDirs as $name => $dir) {
            if (!is_dir($dir)) continue;

            // Check for executable files in upload directories
            $files = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::SELF_FIRST
            );

            $badFiles = [];
            foreach ($files as $file) {
                if (!$file->isFile()) continue;
                $ext = strtolower($file->getExtension());
                if (in_array($ext, self::NOT_ALLOWED_IN_UPLOAD)) {
                    $badFiles[] = $file->getRealPath();
                    if (count($badFiles) >= 5) break;
                }
            }

            if (!empty($badFiles)) {
                $severity = $name === 'upload' || $name === 'download' ? 'critical' : 'high';
                $findings[] = [
                    'file'     => $badFiles[0],
                    'line'     => 0,
                    'pattern'  => "ps_{$name}_executables",
                    'severity' => $severity,
                    'type'     => 'prestashop',
                    'message'  => count($badFiles) . " executable file(s) found in /$name/ directory.",
                ];
            }
        }

        return $findings;
    }

    private function checkHtaccess(): array
    {
        $findings = [];

        $htFiles = [
            $this->path . '/.htaccess',
            $this->path . '/admin/.htaccess',
        ];

        foreach ($htFiles as $ht) {
            if (!file_exists($ht)) continue;
            $content = file_get_contents($ht);
            if (!$content) continue;

            if (str_contains($content, 'RewriteEngine On')) {
                // Good - RewriteEngine is on
            } else {
                $name = basename(dirname($ht));
                $findings[] = [
                    'file'     => $ht,
                    'line'     => 0,
                    'pattern'  => 'ps_no_rewrite',
                    'severity' => 'medium',
                    'type'     => 'prestashop',
                    'message'  => "$name .htaccess missing RewriteEngine. Friendly URLs may be disabled.",
                ];
            }
        }

        // Check if main .htaccess exists
        if (!file_exists($this->path . '/.htaccess')) {
            $findings[] = [
                'file'     => $this->path,
                'line'     => 0,
                'pattern'  => 'ps_missing_htaccess',
                'severity' => 'high',
                'type'     => 'prestashop',
                'message'  => 'Root .htaccess missing. PrestaShop requires it for URL rewriting and security rules.',
            ];
        }

        return $findings;
    }

    private function checkSslConfig(): array
    {
        $findings = [];

        // Check PrestaShop 1.6 config
        $settingsFile = $this->path . '/config/settings.inc.php';
        if (file_exists($settingsFile)) {
            $content = file_get_contents($settingsFile);
            if ($content && preg_match('/_PS_SSL_ENABLED_\s*,\s*false/i', $content)) {
                $findings[] = [
                    'file'     => $settingsFile,
                    'line'     => 0,
                    'pattern'  => 'ps_ssl_disabled',
                    'severity' => 'high',
                    'type'     => 'prestashop',
                    'message'  => 'SSL is disabled in PrestaShop configuration. Customer data transmitted in plaintext.',
                ];
            }
        }

        // Check PrestaShop 1.7+ config in database parameters
        $parametersFile = $this->path . '/app/config/parameters.php';
        if (file_exists($parametersFile)) {
            $content = file_get_contents($parametersFile);
            if ($content && preg_match('/_PS_SSL_ENABLED_\s*["\']?\s*=>\s*["\']?0/i', $content)) {
                $findings[] = [
                    'file'     => $parametersFile,
                    'line'     => 0,
                    'pattern'  => 'ps_ssl_disabled_17',
                    'severity' => 'high',
                    'type'     => 'prestashop',
                    'message'  => 'SSL is disabled (parameters.php). Enable SSL for secure customer transactions.',
                ];
            }
        }

        return $findings;
    }

    private function checkBackdoorFiles(): array
    {
        $findings = [];

        $backdoorNames = [
            'XsamXadoo_Bot.php', 'XsamXadoo_deface.php', '0x666.php',
            'f.php', 'Xsam_Xadoo.html', 'XsamXadoo.html',
            'shell.php', 'shell.php5', 'cmd.php', 'wso.php',
            'backdoor.php', 'backdoor.php5', 'c99.php', 'c99.txt',
            'r57.php', 'r57.txt', 'b374k.php', 'b374k.txt',
            'webshell.php', 'webadmin.php', 'php_console.php',
            'hacker.php', '1337.php', 'x.php', 'safe.php',
            '404.php', 'adminer.php', 'phpmyadmin.php',
        ];

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($this->path, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::SELF_FIRST
        );

        $found = 0;
        foreach ($iterator as $file) {
            if (!$file->isFile()) continue;
            $basename = $file->getBasename();
            if (in_array($basename, $backdoorNames)) {
                $findings[] = [
                    'file'     => $file->getRealPath(),
                    'line'     => 0,
                    'pattern'  => 'ps_backdoor_filename',
                    'severity' => 'critical',
                    'type'     => 'prestashop',
                    'message'  => "Known backdoor file detected: $basename",
                ];
                $found++;
                if ($found >= 10) break;
            }
        }

        return $findings;
    }

    private function checkKnownInfectedFiles(): array
    {
        $findings = [];

        $infectedPaths = [
            '/controllers/front/IndexController.php',
            '/modules/bankwire/controllers/front/validation.php',
            '/tools/smarty/sysplugins/smarty_cacheresource.php',
            '/tools/smarty/sysplugins/smarty_internal_data.php',
            '/cache/tcpdf/index.php',
            '/cache/smarty/cache/index.php',
            '/cache/smarty/compile/index.php',
            '/classes/Dispatcher.php',
            '/classes/Hook.php',
            '/classes/Product.php',
            '/classes/Store.php',
            '/classes/Tools.php',
            '/classes/controller/Controller.php',
            '/classes/controller/FrontController.php',
            '/classes/controller/ModuleFrontController.php',
            '/classes/shop/Shop.php',
        ];

        foreach ($infectedPaths as $relPath) {
            $fullPath = $this->path . $relPath;
            if (!file_exists($fullPath)) continue;

            $content = @file_get_contents($fullPath);
            if (!$content) continue;

            if (preg_match('/\beval\s*\(\s*base64_decode\s*\(/i', $content) ||
                preg_match('/\$\w+\s*=\s*\$[a-z]+\d*\[/', $content) ||
                preg_match('/\bgzuncompress\s*\(\s*base64_decode\s*\(/i', $content) ||
                preg_match('/\$_(?:GET|POST|REQUEST|COOKIE)\[.*?\]\s*\(\s*\$/', $content) ||
                preg_match('/\/\*[\w\s]+\*\/\s*\w+\s*=\s*\w+/', $content) ||
                preg_match('/preg_replace\s*\(\s*["\'].*?e["\']\s*,/i', $content)) {
                $findings[] = [
                    'file'     => $fullPath,
                    'line'     => 0,
                    'pattern'  => 'ps_infected_core_file',
                    'severity' => 'critical',
                    'type'     => 'prestashop',
                    'message'  => "Potentially infected core file: " . basename($relPath) . " (contains obfuscated code)",
                ];
            }
        }

        return $findings;
    }

    private function checkThemeSkimmers(): array
    {
        $findings = [];
        $themesDir = $this->path . '/themes';

        if (!is_dir($themesDir)) return $findings;

        $themeFiles = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($themesDir, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($themeFiles as $file) {
            if (!$file->isFile()) continue;
            $ext = strtolower($file->getExtension());
            if (!in_array($ext, ['tpl', 'html', 'php'])) continue;
            if ($file->getSize() > 500000) continue;

            $content = @file_get_contents($file->getRealPath());
            if (!$content) continue;

            if (preg_match('/<script[^>]*>\s*var\s+\w+\s*=\s*atob\s*\(/', $content) ||
                preg_match('/<script[^>]*>\s*document\s*\.\s*write\s*\(\s*atob\s*\(/', $content) ||
                preg_match('/atob\s*\(\s*["\'][A-Za-z0-9+\/=]{100,}["\']\s*\)/', $content) ||
                preg_match('/wss?:\/\/[a-z0-9]+(?:store|xyz|top|click|bid|trade)[^"\']*\/[a-z]+/', $content) ||
                preg_match('/\.onerror\s*=|\.onload\s*=|\.onmouseover\s*=/', $content) ||
                preg_match('/\bnavigator\s*\.\s*userAgent\s*\.\s*(?:match|indexOf|toLowerCase)/', $content)) {
                $findings[] = [
                    'file'     => $file->getRealPath(),
                    'line'     => 0,
                    'pattern'  => 'ps_theme_skimmer',
                    'severity' => 'critical',
                    'type'     => 'prestashop',
                    'message'  => "Possible digital skimmer in theme template: " . $file->getBasename(),
                ];
            }
        }

        return $findings;
    }

    private function checkAdminEvasion(): array
    {
        $findings = [];

        $phpFiles = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($this->path, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::SELF_FIRST
        );

        $checked = 0;
        foreach ($phpFiles as $file) {
            if (!$file->isFile()) continue;
            if ($file->getExtension() !== 'php') continue;
            if ($file->getSize() > 200000) continue;
            $checked++;
            if ($checked > 500) break;

            $content = @file_get_contents($file->getRealPath());
            if (!$content) continue;

            if (preg_match('/isset\s*\(\s*\$GLOBALS\s*\[\s*[\'"]employee[\'"]\s*\)/', $content) ||
                preg_match('/\$GLOBALS\s*\[\s*[\'"]employee[\'"]\s*\]/', $content) ||
                preg_match('/isset\s*\(\s*\$GLOBALS\s*\[\s*[\'"]prestashop[\'"]\s*\]\s*\[\s*[\'"]employee[\'"]\s*\]/', $content) ||
                preg_match('/#header_employee_box/', $content) ||
                preg_match('/["\']psAdmin["\']/', $content) ||
                preg_match('/preg_match\s*\(\s*["\']\/admin/i', $content)) {
                $findings[] = [
                    'file'     => $file->getRealPath(),
                    'line'     => 0,
                    'pattern'  => 'ps_admin_evasion',
                    'severity' => 'critical',
                    'type'     => 'prestashop',
                    'message'  => "Admin detection evasion code detected in: " . $file->getBasename(),
                ];
            }
        }

        return $findings;
    }

    private function checkPhpUnitVulns(): array
    {
        $findings = [];
        $modulesDir = $this->path . '/modules';

        if (!is_dir($modulesDir)) return $findings;

        $moduleDirs = new \FilesystemIterator($modulesDir, \FilesystemIterator::SKIP_DOTS);
        foreach ($moduleDirs as $module) {
            if (!$module->isDir()) continue;

            $vendorDir = $module->getRealPath() . '/vendor';
            if (!is_dir($vendorDir)) continue;

            $phpunitAutoload = $vendorDir . '/phpunit/phpunit/phpunit';
            if (!file_exists($phpunitAutoload)) continue;

            $composerJson = $module->getRealPath() . '/composer.json';
            $phpunitVersion = null;

            if (file_exists($composerJson)) {
                $json = @file_get_contents($composerJson);
                if ($json) {
                    $data = json_decode($json, true);
                    if ($data && isset($data['require']['phpunit/phpunit'])) {
                        $phpunitVersion = $data['require']['phpunit/phpunit'];
                    } elseif ($data && isset($data['require-dev']['phpunit/phpunit'])) {
                        $phpunitVersion = $data['require-dev']['phpunit/phpunit'];
                    }
                }
            }

            if ($phpunitVersion) {
                $versionClean = ltrim($phpunitVersion, '^~>=<!');
                if (version_compare($versionClean, '7.5.19', '<') && str_starts_with($versionClean, '7')) {
                    $findings[] = [
                        'file'     => $module->getRealPath() . '/composer.json',
                        'line'     => 0,
                        'pattern'  => 'ps_phpunit_vuln',
                        'severity' => 'high',
                        'type'     => 'prestashop',
                        'message'  => "Module '{$module->getBasename()}' bundles PHPUnit $phpunitVersion (< 7.5.19) - known CVE-2017-9841 vulnerability",
                    ];
                } elseif (version_compare($versionClean, '8.5.1', '<') && str_starts_with($versionClean, '8')) {
                    $findings[] = [
                        'file'     => $module->getRealPath() . '/composer.json',
                        'line'     => 0,
                        'pattern'  => 'ps_phpunit_vuln',
                        'severity' => 'high',
                        'type'     => 'prestashop',
                        'message'  => "Module '{$module->getBasename()}' bundles PHPUnit $phpunitVersion (< 8.5.1) - known CVE-2017-9841 vulnerability",
                    ];
                }
            } else {
                $findings[] = [
                    'file'     => $phpunitAutoload,
                    'line'     => 0,
                    'pattern'  => 'ps_phpunit_present',
                    'severity' => 'medium',
                    'type'     => 'prestashop',
                    'message'  => "Module '{$module->getBasename()}' bundles PHPUnit without explicit version in composer.json. Check manually for CVE-2017-9841.",
                ];
            }
        }

        return $findings;
    }

    private function isCoreModule(string $name): bool
    {
        $coreModules = [
            'ps_mainmenu', 'ps_searchbar', 'ps_imageslider', 'ps_featuredproducts',
            'ps_banner', 'ps_customtext', 'ps_linklist', 'ps_contactinfo',
            'ps_currencyselector', 'ps_languageselector', 'ps_shoppingcart',
            'ps_customeraccountlinks', 'ps_categorytree', 'ps_socialfollow',
            'ps_sharebuttons', 'ps_wirepayment', 'ps_checkpayment',
            'ps_banktransfer', 'ps_cashondelivery', 'blockcart', 'blockcurrencies',
            'blocklanguages', 'blockcontact', 'blockcontactinfos', 'blockcms',
            'blockcmsinfo', 'blockmyaccount', 'blocknewproducts', 'blocknewsletter',
            'blockpaymentlogo', 'blocksocial', 'blockspecials', 'blocksupplier',
            'blocktags', 'blockuserinfo', 'blockviewed', 'blockwishlist',
            'blockmanufacturer', 'blockbestsellers', 'blocksearch',
            'blocktopmenu', 'blockadvertising', 'blockpermanentlinks',
            'blockstore', 'blockrss', 'blockcurrencys', 'statsdata',
            'statsmodule', 'statsvisits', 'statspersonalinfos', 'statsregistrations',
            'statsstock', 'statsbestcustomers', 'statsbestproducts', 'statsbestsuppliers',
            'statsbestcategories', 'statsbestvouchers', 'statsnewsletter',
            'statsequipment', 'statsforecast', 'graphnvd3', 'gridhtml',
            'dashactivity', 'dashgoals', 'dashproducts', 'dashtrends',
            'pagesnotfound', 'sekeywords', 'productcomments', 'gsitemap',
            'cronjobs', 'watermark', 'mobile_theme', 'ps_add2cart',
            'ps_themecustomizer', 'ps_facetedsearch', 'ps_legalcompliance',
            'ps_emailalerts', 'ps_dataprivacy', 'ps_specials',
            'ps_customersignin', 'ps_buybuttonlite', 'blockreassurance',
            'ps_googleanalytics', 'ps_maintenance', 'ps_facebook',
            'ps_distributionapiclient', 'contactform', 'dashtrends',
            'gamification', 'welcome', 'ps_metrics', 'ps_eventbus',
            'ps_accounts', 'blockmyaccountfooter', 'cartabandonmentpro',
            'gapi', 'simpleimportproduct', 'ets_blog', 'ps_emailsubscription',
            'ph_simpleblog', 'revsliderprestashop', 'ps_themecustomize',
            'zanox', 'paypal', 'ps_stripe', 'ps_braintree',
        ];
        return in_array($name, $coreModules);
    }

    private function isLikelyMalicious(string $content, string $moduleName): bool
    {
        // Count dangerous functions
        $dangerous = ['eval', 'base64_decode', 'exec', 'shell_exec', 'system', 'passthru', 'popen', 'proc_open'];
        $count = 0;
        foreach ($dangerous as $func) {
            if (preg_match('/\b' . $func . '\s*\(/', $content)) $count++;
        }

        if ($count >= 3) return true;

        // Check for eval + base64 combination
        if (preg_match('/\beval\s*\(\s*base64_decode\s*\(/', $content)) return true;

        // Check for user input in dangerous functions
        if (preg_match('/\b(?:exec|system|shell_exec|passthru|eval)\s*\(\s*\$_?(?:GET|POST|REQUEST|COOKIE|SERVER)\[/', $content)) {
            return true;
        }

        return false;
    }
}
