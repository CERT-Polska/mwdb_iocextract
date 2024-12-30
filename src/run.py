import argparse
import logging

from mwdblib import MWDB  # type: ignore

from .api import parse


def main():
    parser = argparse.ArgumentParser(
        description="Test parser on the top mwdb configs"
    )
    parser.add_argument("mwdb_user", help="Mwdb username")
    parser.add_argument("mwdb_pass", help="Mwdb password")
    parser.add_argument(
        "config_id", help="Config to parse", default=None, nargs="?"
    )
    parser.add_argument(
        "-v", "--verbose", help="Print debug logs", action="store_true"
    )
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    mwdb = MWDB()
    mwdb.login(args.mwdb_user, args.mwdb_pass)

    if args.config_id is not None:
        cfg = mwdb.query_config(args.config_id)
        iocs = parse(cfg.family, cfg.cfg)
        print(iocs.prettyprint())
        return

    for cfg in mwdb.recent_configs():
        if cfg.type != "static":
            continue
        print(cfg.family, cfg.id)
        iocs = parse(cfg.family, cfg.cfg)
        print(iocs.prettyprint())
        print()
        continue


if __name__ == "__main__":
    main()
