import json
import os
import shlex
import sys
from pathlib import Path

import click

from .scanner import scan_path


def safe_echo(message="", **kwargs):
    try:
        click.echo(message, **kwargs)
    except UnicodeEncodeError:
        fallback = str(message).encode("ascii", "replace").decode("ascii")
        click.echo(fallback, **kwargs)


@click.group()
def main():
    """ShieldEnv: A local-first security scanner for hardcoded secrets and API keys."""

@main.command()
@click.option("--path", default=".", help="Root directory to scan for secrets.")
@click.option("--format", type=click.Choice(["text", "json", "sarif"]), default="text", help="Output format for scan results.")
@click.option("--verbose", is_flag=True, help="Show ignored paths and scan summary.")
@click.option("--audit", is_flag=True, help="Include suppression and ignore audit data.")
def scan(path, format, verbose, audit):
    """Scan codebases, configuration files, and environment files for exposed secrets."""
    if format == "text":
        safe_echo("🛡️ ShieldEnv: Scanning repository files...")
    
    try:
        result = scan_path(path, verbose=verbose or audit)
    except (RuntimeError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc
    violations = [finding.__dict__ for finding in result.violations]

    if result.errors:
        for error in result.errors:
            safe_echo(f"❌ {error}", err=True)
        raise click.exceptions.Exit(2)
    
    if format == "sarif":
        safe_echo(json.dumps(_to_sarif(result), indent=2))
        if violations or result.errors:
            raise click.exceptions.Exit(1 if violations else 2)
        return

    if format == "json":
        payload = violations
        if audit or verbose:
            payload = {
                "findings": violations,
                "suppressed": result.suppressed,
                "ignored": result.ignored,
                "files_scanned": result.files_scanned,
            }
        safe_echo(json.dumps(payload, indent=2))
        if violations:
            raise click.exceptions.Exit(1)
        return

    if not violations:
        safe_echo("✅ All clear! No leaked secrets or API keys found.")
        if audit or verbose:
            safe_echo(f"Scanned {result.files_scanned} files.")
            safe_echo(f"Suppressed findings: {len(result.suppressed)}")
            safe_echo(f"Ignored paths: {len(result.ignored)}")
        return

    safe_echo(f"\n❌ SECURITY ALERT: Found {len(violations)} potential secret leaks!\n")
    
    for v in violations:
        safe_echo(f"  • Type: {v['type']}")
        safe_echo(f"    File: {v['file']} (Line {v['line']})")
        safe_echo(f"    Confidence: {v['confidence']}")
        safe_echo(f"    Data: {v['snippet']}")
        safe_echo("-" * 50)

    if audit or verbose:
        safe_echo(f"\nSuppressed findings: {len(result.suppressed)}")
        safe_echo(f"Ignored paths: {len(result.ignored)}")
        safe_echo(f"Files scanned: {result.files_scanned}")
        
    safe_echo("\n🚫 Commit/Build BLOCKED. Remove secrets, use environment variables, or update .shieldignore.")
    raise click.exceptions.Exit(1)


def _to_sarif(result):
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "ShieldEnv",
                "informationUri": "https://github.com/ShieldHQ/shieldenv",
                "rules": [
                    {"id": finding.type, "name": finding.type}
                    for finding in result.violations
                ],
            }},
            "results": [{
                "ruleId": finding.type,
                "level": "error" if finding.confidence == "high" else "warning",
                "message": {"text": f"Potential secret detected ({finding.confidence} confidence)."},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": Path(os.path.relpath(finding.file)).as_posix()
                        },
                        "region": {"startLine": finding.line},
                    }
                }],
            } for finding in result.violations],
        }],
    }

@main.command()
@click.option("--force", is_flag=True, help="Back up and replace an existing pre-commit hook.")
def install(force):
    """Automatically install ShieldEnv as a local Git pre-commit hook."""
    git_dir = Path(".git")
    if not git_dir.exists():
        safe_echo("❌ Error: Not a git repository. Run 'git init' first.")
        raise click.exceptions.Exit(1)

    hook_path = git_dir / "hooks" / "pre-commit"
    if hook_path.exists() and not force:
        raise click.ClickException(
            f"{hook_path} already exists; use --force to replace it with a backup."
        )

    if hook_path.exists():
        backup_path = hook_path.with_name("pre-commit.shieldenv-backup")
        hook_path.replace(backup_path)

    if getattr(sys, "frozen", False):
        command = shlex.quote(sys.executable)
    else:
        command = f"{shlex.quote(sys.executable)} -m shieldenv.cli"
    hook_script = f"""#!/bin/sh
# ShieldEnv automated pre-commit security hook
exec {command} scan
"""
    try:
        hook_path.parent.mkdir(parents=True, exist_ok=True)
        with open(hook_path, "w", encoding="utf-8") as f:
            f.write(hook_script)
        
        # Make executable on Unix/Mac
        if os.name != 'nt':
            hook_path.chmod(0o755)
            
        safe_echo("✅ Successfully installed ShieldEnv git pre-commit hook!")
    except OSError as e:
        safe_echo(f"❌ Failed to install hook: {e}")
        raise click.exceptions.Exit(1)

if __name__ == "__main__":
    main()