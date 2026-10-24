import time
from pathlib import Path

from shieldenv.scanner import scan_path


def fake_token(prefix: str, suffix: str) -> str:
    return prefix + suffix


def test_detects_aws_key(tmp_path: Path) -> None:
    target = tmp_path / "settings.py"
    target.write_text(
        f'AWS_KEY = "{fake_token("AKIA", "1234567890ABCDEF")}"\n',
        encoding="utf-8",
    )

    result = scan_path(tmp_path)

    assert result.has_secrets
    assert result.findings[0].rule == "AWS access key"


def test_respects_shieldignore(tmp_path: Path) -> None:
    ignored = tmp_path / "secrets.env"
    ignored.write_text(
        f'TOKEN="{fake_token("ghp_", "abcdefghijklmnopqrstuvwxyz")}"\n',
        encoding="utf-8",
    )
    (tmp_path / ".shieldignore").write_text("secrets.env\n", encoding="utf-8")

    result = scan_path(tmp_path)

    assert not result.has_secrets


def test_scans_only_text_files(tmp_path: Path) -> None:
    (tmp_path / "image.bin").write_bytes(b"\xff\xfe\x00")

    result = scan_path(tmp_path)

    assert result.files_scanned == 0


def test_entropy_detection_requires_secret_named_literal_assignment(tmp_path: Path) -> None:
    target = tmp_path / "source.ts"
    target.write_text(
        'const token = "x9Z!mQ8#vL2$pK5_wR7%tY4&hN1-jB3*fC6"\n'
        'const loginPassword = getPassword(token)\n'
        'const value = `reset-password?token=${token}`\n'
        'const passwordInput = React.forwardRef<HTMLInputElement, Props>(fn)\n',
        encoding="utf-8",
    )

    result = scan_path(tmp_path)

    assert len(result.findings) == 1
    assert result.findings[0].line == 1


def test_shieldignore_is_loaded_from_scan_root(tmp_path: Path) -> None:
    ignored_dir = tmp_path / "backend" / "app" / "api"
    ignored_dir.mkdir(parents=True)
    (ignored_dir / "secrets.py").write_text(
        f'TOKEN = "{fake_token("ghp_", "abcdefghijklmnopqrstuvwxyz123456")}"\n',
        encoding="utf-8",
    )
    (tmp_path / ".shieldignore").write_text("backend/app/api/\n", encoding="utf-8")

    result = scan_path(tmp_path)

    assert not result.has_secrets


def test_scans_json_and_typed_assignments(tmp_path: Path) -> None:
    (tmp_path / "config.json").write_text(
        f'{{"password": "{fake_token("ghp_", "abcdefghijklmnopqrstuvwxyz123456")}"}}\n',
        encoding="utf-8",
    )
    (tmp_path / "config.py").write_text(
        f'password: str = "{fake_token("ghp_", "abcdefghijklmnopqrstuvwxyz123456")}"\n',
        encoding="utf-8",
    )

    result = scan_path(tmp_path)

    assert len(result.findings) == 2


def test_ignore_names_match_path_segments_not_substrings(tmp_path: Path) -> None:
    (tmp_path / "apiary.py").write_text(
        f'TOKEN = "{fake_token("ghp_", "abcdefghijklmnopqrstuvwxyz123456")}"\n',
        encoding="utf-8",
    )
    (tmp_path / "api").mkdir()
    (tmp_path / "api" / "safe.py").write_text("print('safe')\n", encoding="utf-8")
    (tmp_path / ".shieldignore").write_text("api\n", encoding="utf-8")

    result = scan_path(tmp_path)

    assert len(result.findings) == 1
    assert result.findings[0].file.endswith("apiary.py")


def test_provider_findings_are_redacted_and_have_confidence(tmp_path: Path) -> None:
    (tmp_path / "providers.env").write_text(
        f'OPENAI_KEY={fake_token("sk-", "abcdefghijklmnopqrstuvwxyz1234567890")}\n'
        f'AWS_KEY={fake_token("AKIA", "1234567890ABCDEF")}\n'
        f'STRIPE_KEY={fake_token("sk_live_", "12345678901234567890")}\n',
        encoding="utf-8",
    )

    result = scan_path(tmp_path)

    assert len(result.findings) == 3
    assert all(finding.snippet == "[REDACTED]" for finding in result.findings)
    assert all(finding.confidence == "high" for finding in result.findings)


def test_inline_suppression_is_recorded(tmp_path: Path) -> None:
    (tmp_path / "source.py").write_text(
        f'TOKEN = "{fake_token("ghp_", "abcdefghijklmnopqrstuvwxyz123456")}"  # shieldenv: ignore\n',
        encoding="utf-8",
    )

    result = scan_path(tmp_path)

    assert not result.findings
    assert result.suppressed[0]["line"] == 1


def test_structured_config_extensions_are_scanned(tmp_path: Path) -> None:
    (tmp_path / "config.yaml").write_text(
        f'password: {fake_token("ghp_", "abcdefghijklmnopqrstuvwxyz123456")}\n',
        encoding="utf-8",
    )
    (tmp_path / "config.toml").write_text(
        f'token = "{fake_token("ghp_", "abcdefghijklmnopqrstuvwxyz123456")}"\n',
        encoding="utf-8",
    )

    result = scan_path(tmp_path)

    assert len(result.findings) == 2


def test_large_repository_scan_completes(tmp_path: Path) -> None:
    for index in range(250):
        (tmp_path / f"module_{index}.py").write_text(
            "def health_check():\n    return True\n",
            encoding="utf-8",
        )

    started = time.perf_counter()
    result = scan_path(tmp_path)
    elapsed = time.perf_counter() - started

    assert result.files_scanned == 250
    assert not result.findings
    assert elapsed < 2.0


def test_provider_fixture_detects_and_redacts_all_supported_rules(tmp_path: Path) -> None:
    target = tmp_path / "providers.env"
    target.write_text(
        f'OPENAI={fake_token("sk-", "abcdefghijklmnopqrstuvwxyz1234567890")}\n'
        f'ANTHROPIC={fake_token("sk-ant-", "abcdefghijklmnopqrstuvwxyz")}\n'
        f'GOOGLE={fake_token("AIza", "12345678901234567890123456789012345")}\n'
        f'AWS={fake_token("AKIA", "1234567890ABCDEF")}\n'
        f'GITHUB={fake_token("ghp_", "abcdefghijklmnopqrstuvwxyz123456")}\n'
        f'SLACK={fake_token("xoxb-", "1234567890-abcdefghijklmnop")}\n'
        f'STRIPE={fake_token("sk_live_", "12345678901234567890")}\n',
        encoding="utf-8",
    )
    findings = scan_file_for_fixture(target)

    assert len(findings) == 7
    assert {finding.confidence for finding in findings} == {"high"}
    assert all(finding.snippet == "[REDACTED]" for finding in findings)


def scan_file_for_fixture(path: Path):
    from shieldenv.scanner import scan_file_details

    findings, _ = scan_file_details(path)
    return findings
