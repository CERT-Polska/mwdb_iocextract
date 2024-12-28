from typing import Any, Dict

from . import modules
from .model import IocCollection


def parse(family: str, config: Dict[str, Any]) -> IocCollection:
    """Parse a mwdb static config of the given family, and get a IocCollection

    :param family: Family this config belongs to
    :param config: MWDB configuration dict"""
    iocs = IocCollection(family)
    if family in modules.modules:
        modules.modules[family](config, iocs)

    modules.parse(config, iocs)
    return iocs
