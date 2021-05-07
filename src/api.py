from . import modules
from .model import IocCollection
from typing import Dict, Any


def parse(family: str, config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    if family in modules.modules:
        iocs = modules.modules[family](config)

    modules.parse(config, iocs)

    return iocs
