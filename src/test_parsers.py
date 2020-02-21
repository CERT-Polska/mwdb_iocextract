from .api import parse
import argparse
from mwdblib import Malwarecage  # type: ignore


def main():
    parser = argparse.ArgumentParser(
        description="Test parser on the top mwdb configs"
    )
    parser.add_argument("mwdb_user", help="Mwdb username")
    parser.add_argument("mwdb_pass", help="Mwdb password")
    args = parser.parse_args()

    mwdb = Malwarecage()
    mwdb.login(args.mwdb_user, args.mwdb_pass)

    for cfg in mwdb.recent_configs():
        if cfg.type != "static":
            continue
        print(cfg.id)
        iocs = parse(cfg.family, cfg.cfg)
        print(iocs.prettyprint())


if __name__ == "__main__":
    main()
