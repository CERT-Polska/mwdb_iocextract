import argparse
import os
import json
from mwdblib import Malwarecage
from src.api import parse


def main():
    parser = argparse.ArgumentParser(
        description="Generation of json and txt test files for parsing test"
    )
    parser.add_argument("mwdb_user", help="Mwdb username")
    parser.add_argument("mwdb_pass", help="Mwdb password")
    parser.add_argument("mwdb_config_id", nargs="?", help="Config Id", default="")
    args = parser.parse_args()

    current_path = os.path.abspath(os.path.dirname(__file__))
    testdir = current_path + "/testdata/"

    mwdb = Malwarecage()
    mwdb.login(args.mwdb_user, args.mwdb_pass)

    if args.mwdb_config_id:
        mwdb_config = mwdb.query_config(args.mwdb_config_id)

        json_file_name = mwdb_config.family + "_" + args.mwdb_config_id + ".json"
        generate_config_json_file(testdir, json_file_name, mwdb_config)

        txt_file_name = mwdb_config.family + "_" + args.mwdb_config_id + ".txt"
        iocs = parse(mwdb_config.family, mwdb_config.cfg)
        generate_txt_file(testdir, txt_file_name, iocs)
    else:
        families_parsed = []
        for cfg in mwdb.recent_configs():
            if cfg.type != "static":
                continue

            if cfg.family not in families_parsed:
                json_file_name = cfg.family + "_" + cfg.id + ".json"
                generate_config_json_file(testdir, json_file_name, cfg)

                txt_file_name = cfg.family + "_" + cfg.id + ".txt"
                try:
                    iocs = parse(cfg.family, cfg.cfg)
                except:
                    print("Spoiled: "+cfg.id)
                    continue

                generate_txt_file(testdir, txt_file_name, iocs)
                families_parsed.append(cfg.family)


def generate_config_json_file(testdir, json_file_name, mwdb_config):
    with open(testdir+"configs/" + json_file_name, 'w') as fp:
        json.dump(mwdb_config.config_dict, fp)


def generate_txt_file(testdir, txt_file_name, iocs):
    with open(testdir+"expected/" + txt_file_name, 'w') as fp:
        fp.write(iocs.prettyprint()+"\n")


if __name__ == "__main__":
    main()

