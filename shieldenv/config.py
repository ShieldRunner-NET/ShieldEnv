from __future__ import annotations

from pathlib import Path

BUILTIN_IGNORES = {
    "node_modules", "venv", ".venv", "dist", "build", ".next", 
    "__pycache__", ".pytest_cache", ".ruff_cache", ".git", 
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml"
}

def load_shieldignore(root_dir: Path = Path(".")) -> set[str]:
    ignore_set = set(BUILTIN_IGNORES)

    def add_entries(ignore_file: Path) -> None:
        if not ignore_file.exists():
            return
        try:
            lines = ignore_file.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            raise RuntimeError(f"Unable to read ignore file: {ignore_file}") from exc
        for line in lines:
            cleaned = line.strip()
            if cleaned and not cleaned.startswith("#"):
                ignore_set.add(cleaned.strip("/"))

    # 1. Check local project .shieldignore
    add_entries(root_dir / ".shieldignore")

    # 2. Check global user-level ignore (~/.shieldignore)
    add_entries(Path.home() / ".shieldignore")

    return ignore_set
