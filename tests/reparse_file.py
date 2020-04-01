import argparse
import os
import json
from src.api import parse


def reparse_file(path: str) -> None:
    basename = os.path.basename(path)
    print(basename)
    family, rest = basename.split("_")
    sha256, ext = rest.split(".")
    assert ext == "json"

    with open(path) as cfg:
        config = json.loads(cfg.read())

    family = config["type"]
    iocs = parse(family, config)

    result_path = os.path.splitext(path)[0] + ".txt"
    with open(result_path, "w") as fp:
        fp.write(iocs.prettyprint() + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Reparse a single file and save it back"
    )
    parser.add_argument("file_paths", nargs="+")
    args = parser.parse_args()

    for path in args.file_paths:
        reparse_file(path)


if __name__ == "__main__":
    main()
