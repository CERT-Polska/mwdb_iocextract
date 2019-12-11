class IocExtractError(RuntimeError):
    pass


class FamilyNotSupportedYetError(IocExtractError):
    pass


class NotADomainOrIpError(IocExtractError):
    pass


class ModuleAlreadyRegisteredError(IocExtractError):
    pass


class InvalidNetLocError(IocExtractError):
    pass
