from .api import parse
import argparse
from mwdblib import Malwarecage  # type: ignore


def main():
    parser = argparse.ArgumentParser(
        description="Test parser on the top mwdb configs"
    )
    parser.add_argument("mwdb_user", help="Mwdb username")
    parser.add_argument("mwdb_pass", help="Mwdb password")
    parser.add_argument(
        "config_id", help="Config to parse", default=None, nargs="?"
    )
    args = parser.parse_args()

    mwdb = Malwarecage()
    mwdb.login(args.mwdb_user, args.mwdb_pass)

    if args.config_id is not None:
        cfg = mwdb.query_config(args.config_id)
        iocs = parse(cfg.family, cfg.cfg)
        print(iocs.prettyprint())
        return

    for cfg in mwdb.recent_configs():
        if cfg.type != "static":
            continue
        print(cfg.id)
        iocs = parse(cfg.family, cfg.cfg)
        print(iocs.prettyprint())
        continue


if __name__ == "__main__":
    main()
