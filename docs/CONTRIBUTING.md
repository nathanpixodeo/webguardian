# Contributing to WebGuardian

We welcome contributions from the security community! Whether you're reporting bugs, suggesting features, or submitting code changes, your help is appreciated.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Adding Detection Rules](#adding-detection-rules)
- [Adding New Scanners](#adding-new-scanners)
- [Adding New Detectors](#adding-new-detectors)
- [Adding Report Formats](#adding-report-formats)
- [Reporting Security Issues](#reporting-security-issues)

## Code of Conduct

This project adheres to a code of conduct that promotes respectful and constructive collaboration. By participating, you agree to:

- Use welcoming and inclusive language
- Respect differing viewpoints and experiences
- Accept constructive criticism gracefully
- Focus on what is best for the community
- Show empathy towards other community members

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork**:
   ```bash
   git clone https://github.com/your-username/scanner.git
   cd scanner
   ```
3. **Set up the development environment**:
   ```bash
   composer install
   ```
4. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Setup

### Requirements

- PHP 8.0 or higher
- Composer
- PHPUnit 9+ (for running tests)
- A code editor with PHP support

### Installation

```bash
git clone https://github.com/nathanpixodeo/web-guardian.git
cd scanner
composer install
```

### Running Tests

```bash
# Run all tests
composer test

# Run specific test file
php vendor/bin/phpunit tests/ScannerTest.php

# Run with coverage (requires Xdebug or PCOV)
php vendor/bin/phpunit --coverage-html coverage/
```

### Code Style

WebGuardian follows PSR-12 coding standards. We recommend using PHP CS Fixer:

```bash
# Install PHP CS Fixer
composer require --dev friendsofphp/php-cs-fixer

# Check code style
vendor/bin/php-cs-fixer fix --dry-run src/

# Apply code style fixes
vendor/bin/php-cs-fixer fix src/
```

## Coding Standards

### Naming Conventions

- **Classes**: `PascalCase` — `MalwareDetector`, `BackdoorDetector`
- **Methods**: `camelCase` — `scanDirectory()`, `analyzeFile()`
- **Properties**: `camelCase` — `$this->filePath`, `$this->options`
- **Constants**: `UPPER_SNAKE_CASE` — `self::BACKDOOR_THRESHOLD`
- **Variables**: `camelCase` — `$filePath`, `$content`

### File Structure

- One class per file
- Namespace matches directory structure
- Directory names use `PascalCase`
- File names match class names

### Documentation

- All public methods must have PHPDoc blocks
- Complex logic should include inline comments
- Use complete sentences in documentation

```php
/**
 * Scans a directory for malicious patterns using heuristics.
 *
 * @param string $path The absolute path to scan
 * @param array  $options Scan configuration options
 * @return array Array of finding arrays
 */
public function scanDirectory(string $path, array $options = []): array
```

### Type Safety

- Use strict type declarations (`declare(strict_types=1)`)
- Use PHP 8.0 type system features (union types, mixed types)
- Avoid dynamic type coercion

## Testing

### Test Requirements

- All new features must include tests
- Bug fixes should include a regression test
- Tests must pass before pull requests are merged

### Test Structure

```php
<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use WebGuardian\Detector\MalwareDetector;

class MalwareDetectorTest extends TestCase
{
    private MalwareDetector $detector;

    protected function setUp(): void
    {
        $this->detector = new MalwareDetector();
    }

    public function testDetectsBase64EvalPattern(): void
    {
        $content = '<?php eval(base64_decode("dGVzdA==")); ?>';
        $findings = $this->detector->analyze('/test.php', $content);

        $this->assertCount(1, $findings);
        $this->assertEquals('base64_eval_payload', $findings[0]['pattern']);
        $this->assertEquals('critical', $findings[0]['severity']);
    }

    public function testCleanFilePasses(): void
    {
        $content = '<?php echo "Hello, World!"; ?>';
        $findings = $this->detector->analyze('/clean.php', $content);

        $this->assertEmpty($findings);
    }
}
```

### Running Tests

```bash
# Quick test run
php vendor/bin/phpunit

# Verbose output
php vendor/bin/phpunit --verbose

# Test specific directory
php vendor/bin/phpunit tests/Detector/
```

## Pull Request Process

1. **Ensure tests pass**: Run `composer test` before submitting
2. **Update documentation**: Update relevant doc files for any changed behavior
3. **Add test coverage**: New features must include tests
4. **Keep PRs focused**: One feature/fix per pull request
5. **Use descriptive titles**: "Add XSS detection for Laravel Blade templates" not "Update stuff"
6. **Reference issues**: Link related issues in the PR description
7. **Sign your commits**: Use GPG or SSH signing

### PR Checklist

- [ ] Tests pass (`composer test`)
- [ ] Code follows PSR-12 standards
- [ ] Documentation updated
- [ ] CHANGELOG.md updated (if applicable)
- [ ] Commits are signed

## Adding External Rule Sources

To add a new external source to the auto-update pipeline:

1. **Edit** `tools/config/rules-sources.json`
2. **Add** a new entry with `id`, `type` (`yara` or `webguardian_json`), `url`, and `severity_map`
3. **Test** with `./tools/update-rules.sh --source=<id>`
4. **Verify** the converted JSON in `rules/external/`
5. **Submit PR** with the updated config

## Adding Detection Rules

1. **Research the threat**: Understand the pattern you're detecting
2. **Create a test file**: Add sample malicious and clean code samples
3. **Write the pattern**: Add to appropriate `rules/*.json` file
4. **Test thoroughly**: Run against both malicious and clean code
5. **Submit PR**: Include test files and updated rule files

### Rule Creation Checklist

- [ ] Pattern is tested against known malware samples
- [ ] Pattern does not produce false positives on clean code
- [ ] Severity is appropriately assigned
- [ ] Message is clear and actionable
- [ ] Pattern is optimized for performance

## Adding New Scanners

1. **Create scanner class** in `src/Scanner/`
2. **Implement `scan(): array` method**
3. **Add auto-detection** in `bin/webguardian`
4. **Register in Scanner** by adding to the `run()` switch
5. **Write tests** for CMS-specific checks
6. **Add documentation** for new checks

## Adding New Detectors

1. **Create detector class** in `src/Detector/`
2. **Implement analysis methods**
3. **Register in Scanner** constructor and `run()` method
4. **Write comprehensive tests**
5. **Document detection capabilities**

## Adding Report Formats

1. **Create formatter class** in `src/Report/Formatters/`
2. **Implement `format(array $report): string`**
3. **Add format option** in CLI argument parsing
4. **Add documentation** and usage examples

## Reporting Security Issues

If you discover a security vulnerability in WebGuardian itself (not in scanned code), please:

1. **Do not** open a public issue
2. **Email** security@webguardian.dev
3. **Include** detailed description and reproduction steps
4. **Allow** reasonable time for response before disclosure

We will acknowledge receipt within 48 hours and provide a timeline for resolution.

## Release Process

1. Version bump in `composer.json`
2. Update `CHANGELOG.md`
3. Create release tag
4. Build and test release candidate
5. Publish to Packagist (if applicable)
6. Update documentation

## Community

- **GitHub Issues**: Bug reports and feature requests
- **Pull Requests**: Code contributions
- **Security**: Report vulnerabilities privately

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
