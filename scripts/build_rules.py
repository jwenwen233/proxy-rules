from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
from tempfile import NamedTemporaryFile

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.lib.generate import build_all


def write_all_atomically(files: dict[Path, str]) -> None:
    temporary: list[tuple[Path, Path]] = []
    backups: dict[Path, Path | None] = {}
    replaced: list[Path] = []
    try:
        for destination, content in files.items():
            destination.parent.mkdir(parents=True, exist_ok=True)
            with NamedTemporaryFile("w", encoding="utf-8", dir=destination.parent, delete=False) as handle:
                handle.write(content)
                temporary.append((Path(handle.name), destination))
            if destination.exists():
                with NamedTemporaryFile("wb", dir=destination.parent, delete=False) as handle:
                    handle.write(destination.read_bytes())
                    backups[destination] = Path(handle.name)
            else:
                backups[destination] = None
        for temporary_path, destination in temporary:
            os.replace(temporary_path, destination)
            replaced.append(destination)
    except OSError:
        for destination in reversed(replaced):
            backup = backups[destination]
            if backup is None:
                destination.unlink(missing_ok=True)
            else:
                os.replace(backup, destination)
        raise
    finally:
        for temporary_path, _ in temporary:
            temporary_path.unlink(missing_ok=True)
        for backup in backups.values():
            if backup is not None:
                backup.unlink(missing_ok=True)


def generated_files(repo_root: Path) -> set[Path]:
    files: set[Path] = set()
    for directory in (repo_root / "dist/shadowrocket", repo_root / "dist/mihomo"):
        if directory.exists():
            files.update(path for path in directory.rglob("*") if path.is_file())
    return files


def check(files: dict[Path, str], repo_root: Path) -> bool:
    expected = set(files)
    actual = generated_files(repo_root)
    missing = expected - actual
    extra = actual - expected
    changed = {path for path in expected & actual if path.read_text(encoding="utf-8") != files[path]}
    for path in sorted(missing | extra | changed):
        print(path.relative_to(repo_root), file=sys.stderr)
    return not (missing or extra or changed)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build deterministic client rule sets from tracked snapshots.")
    parser.add_argument("--check", action="store_true", help="fail if generated files are missing, extra, or changed")
    args = parser.parse_args()
    repo_root = Path.cwd().resolve()
    files = build_all(repo_root)
    if args.check:
        return 0 if check(files, repo_root) else 1
    write_all_atomically(files)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
