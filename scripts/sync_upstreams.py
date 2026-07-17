from __future__ import annotations

import argparse
from pathlib import Path
import sys

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.lib.upstream import UpstreamError, default_opener, sync_manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Synchronize tracked upstream rule snapshots.")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--update", action="store_true", help="download and write changed snapshots")
    action.add_argument("--check", action="store_true", help="report whether snapshots need updating")
    args = parser.parse_args()
    try:
        result = sync_manifest(Path("source/upstreams.yaml"), Path.cwd(), args.update, default_opener)
    except UpstreamError as error:
        parser.error(str(error))
    return int(args.check and result["changed"])


if __name__ == "__main__":
    raise SystemExit(main())
