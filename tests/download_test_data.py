import argparse
import os
import json
from mwdblib import Malwarecage, MalwarecageConfig  # type: ignore


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Downloading test data from MWDB"
    )
    parser.add_argument("mwdb_user", help="Mwdb username")
    parser.add_argument("mwdb_pass", help="Mwdb password")
    parser.add_argument(
        "mwdb_config_id", nargs="?", help="Config Id", default=""
    )
    args = parser.parse_args()

    current_path = os.path.abspath(os.path.dirname(__file__))
    testdir = current_path + "/testdata/"

    mwdb = Malwarecage()
    mwdb.login(args.mwdb_user, args.mwdb_pass)

    if args.mwdb_config_id:
        mwdb_config = mwdb.query_config(args.mwdb_config_id)

        json_file_name = (
            mwdb_config.family + "_" + args.mwdb_config_id + ".json"
        )
        generate_config_json_file(testdir, json_file_name, mwdb_config)
    else:
        families_parsed = {""}
        for cfg in mwdb.recent_configs():
            if cfg.type != "static":
                continue

            if cfg.family not in families_parsed:
                json_file_name = cfg.family + "_" + cfg.id + ".json"
                generate_config_json_file(testdir, json_file_name, cfg)
                families_parsed.add(cfg.family)


def generate_config_json_file(
    testdir: str, json_file_name: str, mwdb_config: MalwarecageConfig
) -> None:
    with open(testdir + json_file_name, "w") as fp:
        json.dump(mwdb_config.config_dict, fp, sort_keys=True, indent=4)


if __name__ == "__main__":
    main()
