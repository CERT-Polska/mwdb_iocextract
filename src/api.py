from .modules import modules
from .model import IocCollection
from typing import Dict, Any, Optional
from .errors import FamilyNotSupportedYetError


def parse(family: str, config: Dict[str, Any]) -> Optional[IocCollection]:
    if family not in modules:
        raise FamilyNotSupportedYetError(family)

    return modules[family](config)
