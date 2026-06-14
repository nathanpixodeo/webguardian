<?php

namespace WebGuardian\Report;

class ReportGenerator
{
    private array $scanResults;

    public function __construct(array $scanResults)
    {
        $this->scanResults = $scanResults;
    }

    public function generate(): array
    {
        $findings = $this->scanResults['findings'] ?? [];

        // Group by type
        $byType = [];
        foreach ($findings as $f) {
            $type = $f['type'] ?? 'unknown';
            $byType[$type][] = $f;
        }

        // Group by severity
        $bySeverity = [];
        foreach ($findings as $f) {
            $sev = $f['severity'] ?? 'info';
            $bySeverity[$sev][] = $f;
        }

        // Top affected files
        $fileCounts = [];
        foreach ($findings as $f) {
            $file = $f['file'] ?? 'unknown';
            $fileCounts[$file] = ($fileCounts[$file] ?? 0) + 1;
        }
        arsort($fileCounts);
        $topFiles = array_slice($fileCounts, 0, 20);

        return [
            'metadata' => [
                'scanned_at'   => $this->scanResults['scanned_at'] ?? date('c'),
                'path'         => $this->scanResults['path'] ?? '',
                'type'         => $this->scanResults['type'] ?? 'generic',
                'duration_ms'  => $this->scanResults['stats']['elapsed_ms'] ?? 0,
                'files_scanned' => $this->scanResults['stats']['files_scanned'] ?? 0,
                'files_skipped' => $this->scanResults['stats']['files_skipped'] ?? 0,
                'scanner_version' => '1.0.0',
            ],
            'summary' => $this->scanResults['summary'],
            'by_type' => $byType,
            'by_severity' => $bySeverity,
            'top_files' => $topFiles,
            'findings' => $findings,
        ];
    }
}
