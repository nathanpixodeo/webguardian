<?php

namespace WebGuardian\Report\Formatters;

class JsonFormatter
{
    public function format(array $report): string
    {
        $output = $report;

        // Remove the full findings from the output if there are too many to keep manageable
        // but still include them in a separate key
        $output['report_generated_at'] = date('c');
        $output['scanner'] = 'WebGuardian v1.0.0';

        return json_encode($output, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
    }
}
