from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path

from .config import load_shieldignore
from .patterns import PATTERN_RULES

SECRET_ASSIGNMENT = re.compile(
    r"^\s*(?:(?:export\s+)?(?:const|let|var)\s+)?"
    r"(?P<name>[A-Za-z_][\w.]*)"
    r"(?:\s*:\s*[^=]+)?\s*=\s*(?P<value>.+)$"
)

@dataclass
class Finding:
    file: str
    line: int
    type: str
    snippet: str
    confidence: str = "medium"

    @property
    def rule(self) -> str:
        return self.type

@dataclass
class ScanResult:
    violations: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    errors: list[str] = field(default_factory=list)
    suppressed: list[dict[str, str | int]] = field(default_factory=list)
    ignored: list[str] = field(default_factory=list)

    @property
    def findings(self) -> list[Finding]:
        return self.violations

    @property
    def has_secrets(self) -> bool:
        return len(self.violations) > 0

EXCLUDE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".ico", ".pdf", ".lock", ".zip", ".tar", ".gz", 
    ".pyc", ".woff", ".woff2", ".bin", ".md", ".markdown", ".txt"
}

def calculate_entropy(data: str) -> float:
    """Calculates Shannon entropy to detect randomized strings/secrets."""
    if not data:
        return 0.0
    counts = Counter(data)
    return -sum((count / len(data)) * math.log2(count / len(data)) for count in counts.values())

def redact(text: str, match: re.Match[str] | None = None) -> str:
    return "[REDACTED]"


def scan_file_details(file_path: Path) -> tuple[list[Finding], list[dict[str, str | int]]]:
    violations = []
    suppressed = []
    file_str = str(file_path).lower()
    
    if ".test." in file_str or ".spec." in file_str or "tests" in file_path.parts:
        return violations, suppressed

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_no, line in enumerate(f, 1):
                stripped = line.strip()
                lower_line = stripped.lower()
                suppressed_line = "shieldenv: ignore" in lower_line

                if stripped.startswith(("#", "//")) or len(stripped) < 8:
                    continue
                
                if any(term in lower_line for term in ["example", "placeholder", "dummy", "changeme", "your_", "secret123"]):
                    continue

                if "{{" in stripped or "}}" in stripped or "{%" in stripped or "%}" in stripped:
                    continue

                if "${" in stripped or "$(" in stripped:
                    continue

                if (
                    any(safe_call in lower_line for safe_call in ["os.getenv", "settings.", "process.env", "config."])
                    and "=" in stripped
                    and not any(quote in stripped for quote in ["'", '"', "`"])
                ):
                    continue

                if file_path.suffix in {".tsx", ".jsx", ".html", ".vue"}:
                    if any(tag in lower_line for tag in ["<h1", "<h3", "<span", "<div", "routerlink", "tabindex", "datakey"]):
                        continue
                    if "password" in lower_line and not "=" in stripped:
                        continue

                if len(stripped) > 300:
                    continue

                matched = False
                for rule in PATTERN_RULES:
                    match = rule.pattern.search(line)
                    if match:
                        finding = Finding(
                            file=str(file_path),
                            line=line_no,
                            type=rule.name,
                            snippet=redact(stripped, match),
                            confidence=rule.confidence,
                        )
                        if suppressed_line:
                            suppressed.append({"file": str(file_path), "line": line_no, "reason": "inline suppression"})
                        else:
                            violations.append(finding)
                        matched = True
                        break
                
                if matched:
                    continue

                assignment = SECRET_ASSIGNMENT.match(stripped)
                if assignment and any(
                    word in assignment.group("name").lower()
                    for word in ["token", "secret", "password", "api_key", "secret_key"]
                ):
                    value = assignment.group("value").strip()
                    literal = re.fullmatch(r"""(['"])(.*?)\1""", value)
                    if literal:
                        val = literal.group(2)
                        if len(val) > 20 and calculate_entropy(val) > 4.5:
                            finding = Finding(
                                file=str(file_path),
                                line=line_no,
                                type="High-Entropy Secret / Custom Token",
                                snippet=redact(stripped),
                                confidence="medium",
                            )
                            if suppressed_line:
                                suppressed.append({"file": str(file_path), "line": line_no, "reason": "inline suppression"})
                            else:
                                violations.append(finding)
    except (OSError, UnicodeError) as exc:
        raise RuntimeError(f"Unable to scan file: {file_path}") from exc
    return violations, suppressed


def scan_file(file_path: Path) -> list[Finding]:
    return scan_file_details(file_path)[0]

def scan_path(root_dir=".", verbose=False):
    root_path = Path(root_dir).resolve()
    if not root_path.exists():
        raise ValueError(f"Scan path does not exist: {root_path}")
    if not root_path.is_dir():
        raise ValueError(f"Scan path is not a directory: {root_path}")

    ignore_list = load_shieldignore(root_path)
    all_violations = []
    errors = []
    suppressed = []
    ignored = []
    files_count = 0

    for path in root_path.rglob("*"):
        rel_path = path.relative_to(root_path)
        rel_str = rel_path.as_posix()
        if any(_matches_ignore(rel_str, path.is_dir(), ignore) for ignore in ignore_list):
            if verbose:
                ignored.append(rel_str)
            continue

        if path.is_dir():
            continue
        if path.suffix.lower() in EXCLUDE_EXTENSIONS:
            continue
            
        files_count += 1
        try:
            findings, audits = scan_file_details(path)
            all_violations.extend(findings)
            suppressed.extend(audits)
        except RuntimeError as exc:
            errors.append(str(exc))

    return ScanResult(
        violations=all_violations,
        files_scanned=files_count,
        errors=errors,
        suppressed=suppressed,
        ignored=ignored,
    )


def _matches_ignore(relative_path: str, is_directory: bool, pattern: str) -> bool:
    normalized = pattern.strip().strip("/")
    if not normalized:
        return False
    if "/" not in normalized and "\\" not in normalized:
        return normalized in Path(relative_path).parts
    if fnmatch(relative_path, normalized) or fnmatch(relative_path, f"{normalized}/**"):
        return True
    return is_directory and relative_path == normalized

def scan_directory(root_dir="."):
    return [v.__dict__ for v in scan_path(root_dir).violations]