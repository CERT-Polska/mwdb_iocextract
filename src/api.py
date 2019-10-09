from .modules import modules
from .model import IocCollection
from typing import Dict, Any


def parse(family: str, config: Dict[str, Any]) -> IocCollection:
    if family not in modules:
        raise RuntimeError(f"Family {family} is not supported by iocextract")

    return modules[family](config)
