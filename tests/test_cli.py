import json

from click.testing import CliRunner

from shieldenv.cli import main


def test_sarif_output_has_standard_shape(tmp_path) -> None:
    (tmp_path / "config.env").write_text(
        "AWS_KEY=AKIA" + "1234567890ABCDEF\n",
        encoding="utf-8",
    )

    result = CliRunner().invoke(main, ["scan", "--path", str(tmp_path), "--format", "sarif"])

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["results"][0]["ruleId"] == "AWS access key"
    assert "AKIA" not in result.output


def test_audit_json_reports_suppression_without_secret(tmp_path) -> None:
    fake_secret = "ghp_" + "abcdefghijklmnopqrstuvwxyz123456"
    (tmp_path / "config.py").write_text(
        f'TOKEN = "{fake_secret}"  # shieldenv: ignore\n',
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        main,
        ["scan", "--path", str(tmp_path), "--format", "json", "--audit"],
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["findings"] == []
    assert len(payload["suppressed"]) == 1
    assert fake_secret not in result.output


def test_sarif_output_handles_relpath_value_error(tmp_path, monkeypatch) -> None:
    (tmp_path / "config.env").write_text(
        "AWS_KEY=AKIA" + "1234567890ABCDEF\n",
        encoding="utf-8",
    )

    def _raise_value_error(path):
        raise ValueError("path is on mount 'C:', start on mount 'D:'")

    monkeypatch.setattr("shieldenv.cli.os.path.relpath", _raise_value_error)

    result = CliRunner().invoke(main, ["scan", "--path", str(tmp_path), "--format", "sarif"])

    assert result.exit_code == 1
    payload = json.loads(result.output)
    uri = payload["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri.endswith("config.env")
