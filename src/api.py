from .modules import modules
from .model import IocCollection
from typing import Dict, Any, Optional
import logging
from .errors import FamilyNotSupportedYetError, IocExtractError


def parse(
    family: str, config: Dict[str, Any], raise_on_not_supported: bool = False
) -> Optional[IocCollection]:
    if family not in modules:
        logging.warning(f"Family %s is not supported by iocextract", family)
        if raise_on_not_supported:
            raise FamilyNotSupportedYetError(family)
        return None

    try:
        return modules[family](config)
    except IocExtractError:
        if raise_on_not_supported:
            raise
        return None
