import argparse
import logging
from pymisp import MISPEvent, PyMISP  # type: ignore
from .errors import FamilyNotSupportedYetError
from mwdblib import Malwarecage  # type: ignore
from .api import parse

logging.basicConfig(level=logging.INFO)


def main():
    parser = argparse.ArgumentParser(
        description="Test of adding event to MISP"
    )
    parser.add_argument("mwdb_user", help="Mwdb username")
    parser.add_argument("mwdb_pass", help="Mwdb password")
    parser.add_argument("config", help="Config")
    parser.add_argument("misp_url", help="Misp url")
    parser.add_argument("misp_key", help="Misp key")
    args = parser.parse_args()

    mwdb = Malwarecage()
    mwdb.login(args.mwdb_user, args.mwdb_pass)

    try:
        cfg = mwdb.query_config(args.config)
        iocs = parse(cfg.family, cfg.cfg)
    except FamilyNotSupportedYetError:
        logging.info("Family %s not supported yet...", cfg.family)
        return

    if not iocs:
        # Nothing actionable found - skip the config
        return

    event = MISPEvent()
    event.add_tag(f"mwdb:family:{cfg.family}")
    event.info = f"Malware configuration ({cfg.family})"

    for o in iocs.to_misp():
        event.add_object(o)

    misp = PyMISP(args.misp_url, args.misp_key, False)
    misp.add_event(event)


if __name__ == "__main__":
    main()
