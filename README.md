# ShieldEnv 🛡️
**Local-First Secret Scanning & Pre-Commit Guardrail**

ShieldEnv is an open-source security engine designed to eliminate accidental credential leaks, API key exposures, and compliance violations before code ever hits version control.

## Why Local-First?

Unlike cloud-based PR scanners that analyze your code after it leaves your machine, ShieldEnv runs entirely local-first. **Zero code, environment variables, or tokens ever leave your local environment.**

## Features

- Regex detection for OpenAI, Anthropic, Google, AWS, GitHub, Slack, database URLs, private keys, and generic secret assignments.
- Provider rules include confidence levels (high or medium).
- Entropy-based detection for literal custom tokens.
- Built-in filtering for placeholders, environment substitutions, templates, and common generated/UI syntax.
- Project and user-level `.shieldignore` support.
- Text, JSON, and SARIF output for local and CI use.
- Optional Git pre-commit hook installation.
- Redacted findings that never print complete secret values.

## Installation

### Option 1: Global Installation via PyPI (Recommended)

Install ShieldEnv globally from the Python Package Index:

```bash
pip install shieldenv
```

### Option 2: Installation from Source (For Development)

Clone the repository and set up a development environment:

```bash
git clone https://github.com/ShieldRunner-NET/ShieldEnv.git
cd ShieldEnv
python -m venv .venv
```

Activate the virtual environment:

On Linux/macOS:

```bash
source .venv/bin/activate
```

On Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install in editable development mode with dev dependencies:

```bash
python -m pip install -e ".[dev]"
```

## Usage

Scan the current repository:

```bash
shieldenv scan
```

Scan another path or emit machine-readable JSON:

```bash
shieldenv scan --path ./src --format json
```

Generate GitHub Code Scanning-compatible SARIF:

```bash
shieldenv scan --path . --format sarif > shieldenv.sarif
```

Use verbose mode to inspect scan coverage and ignored paths:

```bash
shieldenv scan --verbose
```

Run audit checks with JSON output:

```bash
shieldenv scan --audit --format json
```

### Exit Codes

```text
0: No findings and no scan errors.
1: One or more potential secrets were found.
2: One or more files could not be read.
```

## Git Pre-Commit Integration

Install a Git pre-commit hook from the repository root:

```bash
shieldenv install
```

ShieldEnv will not overwrite an existing hook unless explicitly requested using `--force`:

```bash
shieldenv install --force
```

With `--force`, an existing hook is safely saved as `.git/hooks/pre-commit.shieldenv-backup`.

## Ignore Rules

ShieldEnv skips common dependency, build, cache, and lock-file paths by default. Add a project-level `.shieldignore` at the root being scanned, or a global `~/.shieldignore`, with one rule per line:

```text
# Exact directory name anywhere in the tree
generated

# Relative path or glob
backend/app/api/
frontend/generated/**
```

Blank lines and lines beginning with `#` are ignored. Use ignore rules carefully: excluded files are not scanned. `--verbose` lists ignored paths so exclusions can be reviewed.

## Inline Suppressions

To suppress a deliberate test value on one line, use the explicit marker:

```python
TEST_TOKEN = "not-a-credential"  # shieldenv: ignore
```

Suppressions are recorded in audit JSON output. Keep suppressions rare and review them carefully during code review.

## Development & Testing

Run unit tests and lint checks locally:

```bash
python -m pytest
ruff check .
```

## Security Notice & Limitations

ShieldEnv is heuristic-based and should complement, not replace, secret rotation and incident-response procedures. Review findings and maintain project-specific ignore rules for generated code.

ShieldEnv cannot guarantee detection of every secret format. It combines provider signatures, structured assignment patterns, and entropy heuristics, so unusual encodings may be missed and generated or identifier-like values may still require review. The scanner intentionally reports findings without exposing full values. Run it in CI on Linux, Windows, and macOS; the included workflow tests Python 3.9 through 3.13.

Provider signatures are high-confidence indicators; generic assignments and entropy findings are medium-confidence heuristics. A clean scan means no supported rule matched, not that the repository is guaranteed secret-free. Rotate any credential that may have been exposed, and use code review and repository access controls alongside ShieldEnv.

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.
