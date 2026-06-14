<?php

namespace WebGuardian\Report\Formatters;

class HtmlFormatter
{
    public function format(array $report): string
    {
        $meta = $report['metadata'];
        $summary = $report['summary'];

        $severityColors = [
            'critical' => '#dc3545',
            'high'     => '#fd7e14',
            'medium'   => '#ffc107',
            'low'      => '#0d6efd',
            'info'     => '#6c757d',
        ];

        $findingsHtml = '';
        if (!empty($report['findings'])) {
            foreach ($report['findings'] as $finding) {
                $sev = $finding['severity'] ?? 'info';
                $color = $severityColors[$sev] ?? '#6c757d';
                $file = htmlspecialchars($finding['file'] ?? 'N/A');
                $line = (int)($finding['line'] ?? 0);
                $msg  = htmlspecialchars($finding['message'] ?? 'No description');

                $findingsHtml .= <<<HTML
                <tr>
                    <td><span class="severity-badge" style="background: {$color};">{$sev}</span></td>
                    <td>{$msg}</td>
                    <td>{$file}:{$line}</td>
                </tr>
HTML;
            }
        }

        $total = $summary['total'] ?? 0;
        $critical = $summary['critical'] ?? 0;
        $high = $summary['high'] ?? 0;
        $medium = $summary['medium'] ?? 0;
        $low = $summary['low'] ?? 0;
        $info = $summary['info'] ?? 0;
        $filesScanned = $meta['files_scanned'] ?? 0;
        $duration = $meta['duration_ms'] ?? 0;
        $scanType = htmlspecialchars($meta['type'] ?? 'generic');
        $scanTime = htmlspecialchars($meta['scanned_at'] ?? '');
        $scanPath = htmlspecialchars($meta['path'] ?? '');

        $overallStatus = $critical > 0 ? 'Critical' : ($high > 0 ? 'High' : ($medium > 0 ? 'Medium' : ($low > 0 ? 'Low' : 'Clean')));
        $overallColor = $severityColors[lcfirst($overallStatus)] ?? '#28a745';

        return <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebGuardian Security Scan Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
               background: #f8f9fa; color: #333; line-height: 1.6; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #1a1a2e, #16213e);
                  color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }
        .header h1 { font-size: 24px; margin-bottom: 5px; }
        .header .subtitle { color: #aaa; font-size: 14px; }
        .status-banner { padding: 15px 20px; border-radius: 8px; margin-bottom: 20px;
                         font-weight: bold; font-size: 18px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
                       gap: 15px; margin-bottom: 20px; }
        .stat-card { background: white; padding: 20px; border-radius: 8px; text-align: center;
                     box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .stat-card .number { font-size: 32px; font-weight: bold; }
        .stat-card .label { color: #666; font-size: 12px; text-transform: uppercase; margin-top: 5px; }
        .meta-table { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px;
                      box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .meta-table td { padding: 8px 10px; border-bottom: 1px solid #eee; }
        .meta-table td:first-child { font-weight: bold; color: #666; width: 150px; }
        table.findings { width: 100%; border-collapse: collapse; background: white;
                         border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        table.findings th { background: #1a1a2e; color: white; padding: 12px 15px; text-align: left; }
        table.findings td { padding: 10px 15px; border-bottom: 1px solid #eee; font-size: 14px; }
        table.findings tr:hover { background: #f1f3f5; }
        .severity-badge { display: inline-block; padding: 2px 8px; border-radius: 4px;
                          color: white; font-size: 11px; font-weight: bold; text-transform: uppercase; }
        .footer { text-align: center; color: #999; margin-top: 30px; font-size: 12px; }
        @media (max-width: 768px) {
            .stats-grid { grid-template-columns: repeat(2, 1fr); }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 WebGuardian Security Scan Report</h1>
            <div class="subtitle">Generated on {$scanTime} | Scanner v1.0.0</div>
        </div>

        <div class="status-banner" style="background: {$overallColor}20; color: {$overallColor}; border: 2px solid {$overallColor};">
            Overall Status: {$overallStatus}
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="number" style="color: {$severityColors['critical']};">{$critical}</div>
                <div class="label">Critical</div>
            </div>
            <div class="stat-card">
                <div class="number" style="color: {$severityColors['high']};">{$high}</div>
                <div class="label">High</div>
            </div>
            <div class="stat-card">
                <div class="number" style="color: {$severityColors['medium']};">{$medium}</div>
                <div class="label">Medium</div>
            </div>
            <div class="stat-card">
                <div class="number" style="color: {$severityColors['low']};">{$low}</div>
                <div class="label">Low</div>
            </div>
            <div class="stat-card">
                <div class="number" style="color: {$severityColors['info']};">{$info}</div>
                <div class="label">Info</div>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="number">{$total}</div>
                <div class="label">Total Findings</div>
            </div>
            <div class="stat-card">
                <div class="number">{$filesScanned}</div>
                <div class="label">Files Scanned</div>
            </div>
            <div class="stat-card">
                <div class="number">{$duration}ms</div>
                <div class="label">Duration</div>
            </div>
        </div>

        <div class="meta-table">
            <table>
                <tr><td>Scan Path</td><td>{$scanPath}</td></tr>
                <tr><td>CMS Type</td><td>{$scanType}</td></tr>
                <tr><td>Scan Time</td><td>{$scanTime}</td></tr>
            </table>
        </div>

        <h2 style="margin-bottom: 15px;">Findings ({$total})</h2>

        <table class="findings">
            <thead>
                <tr>
                    <th style="width: 100px;">Severity</th>
                    <th>Description</th>
                    <th style="width: 40%;">Location</th>
                </tr>
            </thead>
            <tbody>
                {$findingsHtml}
            </tbody>
        </table>

        {$noFindings}

        <div class="footer">
            <p>Generated by WebGuardian Security Scanner v1.0.0</p>
            <p>This report was automatically generated. Review all findings carefully before taking action.</p>
        </div>
    </div>
</body>
</html>
HTML;
    }
}
