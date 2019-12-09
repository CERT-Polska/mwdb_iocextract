from .modules import modules
from .model import IocCollection
from typing import Dict, Any
import logging


def parse(family: str, config: Dict[str, Any]) -> IocCollection:
    if family not in modules:
        logging.warning(f"Family %s is not supported by iocextract", family)
        raise RuntimeError()
        return IocCollection()

    return modules[family](config)
