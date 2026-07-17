from __future__ import annotations

from pathlib import Path
import sys

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.lib.validation import ValidationError, validate_repository


def main() -> int:
    try:
        validate_repository(Path.cwd())
    except ValidationError as error:
        print(error, file=sys.stderr)
        return 1
    print("validation: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
