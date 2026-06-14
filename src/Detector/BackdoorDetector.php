<?php

namespace WebGuardian\Detector;

class BackdoorDetector
{
    private array $options;

    // Heuristic scoring weights for backdoor detection
    private const WEIGHT_EVAL               = 50;
    private const WEIGHT_BASE64             = 10;
    private const WEIGHT_SYSTEM_CMD         = 40;
    private const WEIGHT_FILE_WRITE         = 25;
    private const WEIGHT_USER_INPUT         = 30;
    private const WEIGHT_OBFUSCATION        = 20;
    private const WEIGHT_NETWORK            = 15;
    private const WEIGHT_VARIABLE_VARIABLE  = 10;
    private const WEIGHT_ANON_FUNC          = 5;

    private const BACKDOOR_THRESHOLD = 70;

    public function __construct(array $options = [])
    {
        $this->options = $options;
    }

    public function analyze(string $filePath, string $content): array
    {
        $findings = [];
        $lines = explode("\n", $content);
        $totalScore = 0;
        $lineScores = [];

        foreach ($lines as $lineNum => $line) {
            $lineScore = $this->scoreLine($line);

            if ($lineScore >= self::BACKDOOR_THRESHOLD) {
                $findings[] = [
                    'file'     => $filePath,
                    'line'     => $lineNum + 1,
                    'pattern'  => 'heuristic_backdoor',
                    'severity' => $lineScore >= 100 ? 'critical' : 'high',
                    'type'     => 'backdoor',
                    'message'  => "Potential backdoor (score: $lineScore) - suspicious combination of dangerous patterns",
                    'context'  => trim(substr($line, 0, 200)),
                    'score'    => $lineScore,
                ];
            }

            $lineScores[$lineNum] = $lineScore;
            $totalScore += $lineScore;
        }

        // File-level analysis
        if ($totalScore >= 300 && empty($findings)) {
            // High cumulative score but no single line crossed threshold
            $maxLine = array_search(max($lineScores), $lineScores);
            $findings[] = [
                'file'     => $filePath,
                'line'     => ($maxLine !== false ? $maxLine + 1 : 0),
                'pattern'  => 'high_cumulative_score',
                'severity' => 'medium',
                'type'     => 'backdoor',
                'message'  => "Suspicious file with high cumulative heuristic score ($totalScore)",
                'context'  => '',
            ];
        }

        // Check for backdoor file naming patterns
        $basename = basename($filePath);
        $backdoorNames = [
            '/^(shell|cmd|eval|adminer|uploader|connector|filesman|filemanager|wp-config|config)\d*\./i',
            '/^(r57|c99|b374k|webshell|backdoor|root)\d*\./i',
            '/^\.(bash_|ssh_|mysql_|ftp_)/',
            '/\b(shell|backdoor|webshell|cmd)\.php$/i',
        ];

        foreach ($backdoorNames as $pattern) {
            if (preg_match($pattern, $basename)) {
                $findings[] = [
                    'file'     => $filePath,
                    'line'     => 0,
                    'pattern'  => 'suspicious_filename',
                    'severity' => 'high',
                    'type'     => 'backdoor',
                    'message'  => "Filename '$basename' matches known backdoor naming pattern",
                ];
                break;
            }
        }

        return $findings;
    }

    private function scoreLine(string $line): int
    {
        $score = 0;
        $line = trim($line);

        if (empty($line) || str_starts_with($line, '//') || str_starts_with($line, '#') || str_starts_with($line, '/*')) {
            return 0;
        }

        // Core dangerous functions
        if (preg_match('/\beval\s*\(/', $line)) {
            $score += self::WEIGHT_EVAL;
            if (preg_match('/\$_?(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\[/', $line)) {
                $score += self::WEIGHT_USER_INPUT * 2;
            }
        }

        // Command execution
        if (preg_match('/\b(?:exec|shell_exec|system|passthru|popen|proc_open|pcntl_exec)\s*\(/', $line)) {
            $score += self::WEIGHT_SYSTEM_CMD;
            if (preg_match('/\$_?(?:GET|POST|REQUEST|COOKIE)\[/', $line)) {
                $score += self::WEIGHT_USER_INPUT;
            }
        }

        // File write operations
        if (preg_match('/\b(?:file_put_contents|fwrite|fputs|chmod)\s*\(/', $line)) {
            $score += self::WEIGHT_FILE_WRITE;
            if (preg_match('/\$_?(?:GET|POST|REQUEST|FILES)\[/', $line)) {
                $score += self::WEIGHT_USER_INPUT;
            }
        }

        // Obfuscation
        if (preg_match('/\bbase64_decode\s*\(/', $line)) {
            $score += self::WEIGHT_BASE64;
            if (preg_match('/[\'"][A-Za-z0-9+\/=]{80,}[\'"]/', $line)) {
                $score += self::WEIGHT_OBFUSCATION;
            }
        }

        if (preg_match('/\b(gzinflate|gzuncompress|gzdecode|str_rot13)\s*\(/', $line)) {
            $score += self::WEIGHT_OBFUSCATION;
        }

        // Network operations
        if (preg_match('/\b(?:curl_exec|curl_multi_exec|fsockopen|pfsockopen|stream_socket_client)\s*\(/', $line)) {
            $score += self::WEIGHT_NETWORK;
            if (preg_match('/\$_?(?:GET|POST|REQUEST|SERVER)\[/', $line)) {
                $score += self::WEIGHT_USER_INPUT;
            }
        }

        // Dynamic execution
        if (preg_match('/\bassert\s*\(/', $line)) {
            $score += self::WEIGHT_EVAL / 2;
            if (preg_match('/\$_?(?:GET|POST|REQUEST)\[/', $line)) {
                $score += self::WEIGHT_USER_INPUT;
            }
        }

        if (preg_match('/\bcreate_function\s*\(/', $line)) {
            $score += self::WEIGHT_ANON_FUNC;
        }

        if (preg_match('/\$\{?\}\s*\(/', $line)) {
            $score += self::WEIGHT_VARIABLE_VARIABLE;
        }

        if (preg_match('/\b(?:call_user_func|call_user_func_array|array_map|array_filter)\s*\(\s*\$_(?:GET|POST|REQUEST)/', $line)) {
            $score += self::WEIGHT_USER_INPUT + self::WEIGHT_EVAL;
        }

        // Opaque variable names (very short or random-looking)
        if (preg_match('/\$\w{1,2}\s*(?:=|\.=)/', $line) && preg_match('/[\'"][A-Za-z0-9+\/=]{50,}[\'"]/', $line)) {
            $score += self::WEIGHT_OBFUSCATION / 2;
        }

        // Multiple dangerous functions on same line
        $dangerCount = 0;
        foreach (['eval', 'base64_decode', 'exec', 'system', 'shell_exec', 'passthru', 'assert',
                  'gzinflate', 'file_put_contents', 'fwrite', 'curl_exec', 'fsockopen'] as $func) {
            if (preg_match('/\b' . preg_quote($func, '/') . '\s*\(/', $line)) {
                $dangerCount++;
            }
        }
        if ($dangerCount >= 2) {
            $score += $dangerCount * 15;
        }

        return $score;
    }

    public function getThreshold(): int
    {
        return self::BACKDOOR_THRESHOLD;
    }
}
