import argparse
import os
import json
from typing import Optional
from src import IocCollection
from src.api import parse


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generation of json and txt test files for parsing test"
    )
    parser.add_argument("family", nargs="?", help="Family", default="")
    parser.add_argument("config_id", nargs="?", help="Config Id", default="")
    args = parser.parse_args()

    current_path = os.path.abspath(os.path.dirname(__file__))
    testdir = current_path + "/testdata/"

    if args.family and args.config_id:
        with open(
            testdir + args.family + "_" + args.config_id + ".json"
        ) as cfg:
            config_raw = cfg.read()
            config = json.loads(config_raw)

        family = config["type"]
        iocs = parse(family, config)

        parsed_txt = testdir + family + "_" + args.config_id + ".txt"
        with open(parsed_txt, "w") as fp:
            fp.write(iocs.prettyprint() + "\n")
    else:
        config_files = [f for f in os.listdir(testdir) if f.endswith(".json")]

        for config_file in config_files:
            with open(testdir + config_file) as cfg:
                config_raw = cfg.read()
                config = json.loads(config_raw)

            iocs = parse(config["type"], config)

            split_filename = config_file.split(".")
            expected_file_txt = split_filename[0] + ".txt"

            parsed_txt = testdir + expected_file_txt
            generate_txt_file(parsed_txt, iocs)


def generate_txt_file(parsed_txt: str, iocs: Optional[IocCollection]) -> None:
    with open(parsed_txt, "w") as fp:
        fp.write(iocs.prettyprint() + "\n")


if __name__ == "__main__":
    main()
