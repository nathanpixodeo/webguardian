<?php

namespace WebGuardian\Report\Formatters;

class ConsoleFormatter
{
    private array $colors;

    public function __construct()
    {
        $this->colors = [
            'critical' => "\033[1;31m",   // Bold Red
            'high'     => "\033[0;31m",   // Red
            'medium'   => "\033[0;33m",   // Yellow
            'low'      => "\033[0;34m",   // Blue
            'info'     => "\033[0;37m",   // White
            'reset'    => "\033[0m",
            'bold'     => "\033[1m",
            'green'    => "\033[0;32m",
            'cyan'     => "\033[0;36m",
        ];
    }

    public function format(array $report): string
    {
        $c = $this->colors;
        $meta = $report['metadata'];
        $summary = $report['summary'];

        $output = PHP_EOL;
        $output .= $c['bold'] . str_repeat('=', 60) . $c['reset'] . PHP_EOL;
        $output .= $c['bold'] . '  WebGuardian Security Scan Report' . $c['reset'] . PHP_EOL;
        $output .= $c['bold'] . str_repeat('=', 60) . $c['reset'] . PHP_EOL;
        $output .= PHP_EOL;

        // Metadata
        $output .= $c['cyan'] . "  Scan Path:    " . $c['reset'] . $meta['path'] . PHP_EOL;
        $output .= $c['cyan'] . "  CMS Type:     " . $c['reset'] . $meta['type'] . PHP_EOL;
        $output .= $c['cyan'] . "  Scan Time:    " . $c['reset'] . $meta['scanned_at'] . PHP_EOL;
        $output .= $c['cyan'] . "  Duration:     " . $c['reset'] . $meta['duration_ms'] . 'ms' . PHP_EOL;
        $output .= $c['cyan'] . "  Files Scanned:" . $c['reset'] . ' ' . $meta['files_scanned'] . PHP_EOL;
        $output .= $c['cyan'] . "  Files Skipped:" . $c['reset'] . ' ' . $meta['files_skipped'] . PHP_EOL;
        $output .= PHP_EOL;

        // Summary
        $output .= $c['bold'] . "  ┌─ Scan Summary ──────────────────────────────" . $c['reset'] . PHP_EOL;
        $output .= $c['bold'] . "  │" . $c['reset'] . PHP_EOL;

        $sevLabels = [
            'critical' => ['Critical', $c['critical']],
            'high'     => ['High',     $c['high']],
            'medium'   => ['Medium',   $c['medium']],
            'low'      => ['Low',      $c['low']],
            'info'     => ['Info',     $c['info']],
        ];

        foreach ($sevLabels as $key => [$label, $color]) {
            $count = $summary[$key] ?? 0;
            $bar = str_repeat('█', min($count, 20));
            $output .= "  │   {$color}{$label}: {$count}{$c['reset']}  {$bar}" . PHP_EOL;
        }

        $total = $summary['total'] ?? 0;
        $severityColor = $total === 0 ? $c['green'] : ($summary['critical'] > 0 ? $c['critical'] : $c['medium']);
        $output .= "  │" . PHP_EOL;
        $output .= "  │   {$c['bold']}Total Findings: {$severityColor}{$total}{$c['reset']}" . PHP_EOL;
        $output .= "  └────────────────────────────────────────────────" . PHP_EOL;
        $output .= PHP_EOL;

        if (empty($report['findings'])) {
            $output .= $c['green'] . "  ✓ No security issues detected." . $c['reset'] . PHP_EOL;
            $output .= PHP_EOL;
            return $output;
        }

        // Findings by severity
        $output .= $c['bold'] . "  FINDINGS BY SEVERITY" . $c['reset'] . PHP_EOL;
        $output .= str_repeat('─', 60) . PHP_EOL;

        foreach (['critical', 'high', 'medium', 'low', 'info'] as $severity) {
            $severityFindings = $report['by_severity'][$severity] ?? [];
            if (empty($severityFindings)) continue;

            $color = $sevLabels[$severity][1];
            $output .= PHP_EOL;
            $output .= "  {$color}{$sevLabels[$severity][0]} ({count($severityFindings)}){$c['reset']}" . PHP_EOL;
            $output .= str_repeat('─', 60) . PHP_EOL;

            foreach (array_slice($severityFindings, 0, 30) as $finding) {
                $file = $finding['file'] ?? 'N/A';
                $line = $finding['line'] ?? 0;
                $msg  = $finding['message'] ?? 'No description';

                $shortFile = strlen($file) > 60 ? '...' . substr($file, -57) : $file;
                $output .= "  {$color}⚠{$c['reset']} {$msg}" . PHP_EOL;
                $output .= "    {$c['cyan']}File:{$c['reset']} {$shortFile}" . PHP_EOL;
                if ($line > 0) {
                    $output .= "    {$c['cyan']}Line:{$c['reset']} {$line}" . PHP_EOL;
                }
                $output .= PHP_EOL;
            }

            if (count($severityFindings) > 30) {
                $output .= "  ... and " . (count($severityFindings) - 30) . " more findings" . PHP_EOL;
                $output .= PHP_EOL;
            }
        }

        // Top affected files
        if (!empty($report['top_files'])) {
            $output .= PHP_EOL;
            $output .= $c['bold'] . "  MOST AFFECTED FILES" . $c['reset'] . PHP_EOL;
            $output .= str_repeat('─', 60) . PHP_EOL;

            $rank = 1;
            foreach ($report['top_files'] as $file => $count) {
                $shortFile = strlen($file) > 60 ? '...' . substr($file, -57) : $file;
                $output .= "  {$rank}. {$shortFile} ({$count} issues)" . PHP_EOL;
                $rank++;
                if ($rank > 10) break;
            }
        }

        $output .= PHP_EOL;
        $output .= $c['bold'] . str_repeat('=', 60) . $c['reset'] . PHP_EOL;
        $output .= PHP_EOL;

        return $output;
    }
}
