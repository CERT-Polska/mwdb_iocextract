from .modules import modules
from .model import IocCollection
from typing import Dict, Any
import logging


class FamilyNotSupportedYetError(RuntimeError):
    pass


def parse(
    family: str, config: Dict[str, Any], raise_on_not_supported: bool = False
) -> IocCollection:
    if family not in modules:
        logging.warning(f"Family %s is not supported by iocextract", family)
        if raise_on_not_supported:
            raise FamilyNotSupportedYetError()
        return IocCollection()

    return modules[family](config)
