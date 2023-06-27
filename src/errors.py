class IocExtractError(RuntimeError):
    """Base class for all IOC extract errors."""

    pass


class FamilyNotSupportedYetError(IocExtractError):
    """Deprecated and never thrown. Do not use."""

    pass


class ModuleAlreadyRegisteredError(IocExtractError):
    """Serious internal error, the sam emodule registered twice"""

    pass
