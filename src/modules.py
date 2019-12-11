from typing import Dict, Any
from .model import RsaKey, NetworkLocation, IocCollection
from .errors import ModuleAlreadyRegisteredError


modules: Dict[str, Any] = {}


def module(name):
    def decorator(func):
        if name in modules:
            raise ModuleAlreadyRegisteredError()
        modules[name] = func
        return func

    return decorator


@module("emotet")
def parse_emotet(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    if "public_key" in config:
        iocs.add_rsa_key(RsaKey.parse_pem(config["public_key"]))
    for url in config.get("urls", []):
        iocs.add_network_location(
            NetworkLocation(host=url["cnc"], port=url["port"])
        )
    return iocs


@module("emotet_spam")
def parse_emotet_spam(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for url in config.get("urls", []):
        iocs.add_network_location(
            NetworkLocation(host=url["cnc"], port=url["port"])
        )
    return iocs


@module("emotet_doc")
def parse_emotet_doc(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for url in config.get("urls", []):
        iocs.add_network_location(NetworkLocation.parse_url(url))
    return iocs


@module("netwire")
def parse_netwire(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for url in config.get("urls", []):
        iocs.add_network_location(
            NetworkLocation(host=url["cnc"], port=url["port"])
        )
    if "password" in config:
        iocs.add_password(config["password"])
    if "mutex" in config:
        iocs.add_mutex(config["mutex"])
    return iocs


@module("avemaria")
def parse_avemaria(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for url in config.get("c2", []):
        iocs.add_network_location(NetworkLocation(host=url["host"]))
    if "drop_name" in config:
        iocs.add_drop_filename(config["drop_name"])
    return iocs


@module("remcos")
def parse_remcos(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for url in config.get("c2", []):
        ip, portstr = url["host"].split(":")
        iocs.add_network_location(NetworkLocation(host=ip, port=int(portstr)))
    return iocs


@module("brushaloader")
def parse_brushaloader(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    if "url" in config:
        iocs.add_network_location(NetworkLocation.parse_url(config["url"]))
    return iocs


@module("ostap")
def parse_ostap(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for url in config.get("urls", []):
        iocs.add_network_location(NetworkLocation.parse_url(url["url"]))
    return iocs


@module("wshrat")
def parse_wshrat(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for url in config.get("c2", []):
        if url.count(":") != 1:
            continue
        ip, portstr = url.split(":")
        iocs.add_network_location(NetworkLocation(ip=ip, port=int(portstr)))
    return iocs


@module("formbook")
def parse_formbook(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for url in config.get("urls", []):
        iocs.add_network_location(NetworkLocation.parse_url(url["url"]))
    return iocs


@module("dharma")
def parse_dharma(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for email in config.get("emails", []):
        iocs.add_email(email)
    return iocs


@module("azorult")
def parse_azorult(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    if "cnc" in config:
        iocs.add_network_location(NetworkLocation.parse_url(config["cnc"]))
    return iocs


@module("lokibot")
def parse_lokibot(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for url in config.get("urls", []):
        iocs.add_network_location(NetworkLocation.parse_url(url["url"]))
    return iocs


@module("danaloader")
def parse_danaloader(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for url in config.get("urls", []):
        iocs.add_network_location(NetworkLocation.parse_url(url["url"]))
    return iocs


@module("evil-pony")
@module("pony")
def parse_evilpony(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for url in config.get("urls", []):
        iocs.add_network_location(NetworkLocation.parse_url(url["url"]))
    return iocs


@module("quasarrat")
def parse_quasarrat(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for url in config.get("hosts", []):
        iocs.add_network_location(NetworkLocation.parse_url(url))

    if "encryption_key" in config:
        iocs.add_password(config["encryption_key"])

    if "install_name" in config:
        iocs.add_drop_filename(config["install_name"])

    if "mutex" in config:
        iocs.add_mutex(config["mutex"])

    return iocs


@module("hawkeye")
def parse_hawkeye(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()

    if "EmailUsername" in config:
        iocs.add_email(config["EmailUsername"])

    if "Mutex" in config:
        iocs.add_mutex(config["Mutex"])

    return iocs


@module("agenttesla")
def parse_agenttesla(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()

    if "email" in config:
        iocs.add_email(config["email"])

    return iocs


@module("isfb")
def isfb(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    if "public_key" in config:
        pk = config["public_key"]
        iocs.add_rsa_key(RsaKey(pk["n"], pk["e"]))

    for domain in config.get("domains", []):
        # TODO: what about fake domains here?
        iocs.add_network_location(NetworkLocation(host=domain["cnc"]))

    for url in config.get("urls", []):
        iocs.add_network_location(NetworkLocation.parse_url(url["url"]))
    return iocs


@module("danabot")
def danabot(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    if "rsa_key" in config:
        iocs.add_rsa_key(RsaKey.parse_base64(config["rsa_key"]))

    for netloc in config.get("urls", []):
        iocs.add_network_location(NetworkLocation(host=netloc))
    return iocs


@module("nanocore")
@module("orcusrat")
@module("testmod")
@module("qakbot")
def nothing_to_extract(config: Dict[str, Any]) -> IocCollection:
    """ Empty parser, when used it means that there's nothing useful to
    extract for this family
    """
    return IocCollection()


@module("mirai")
def parse_mirai(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for cnc in config.get("cncs", []):
        if "host" not in cnc:
            continue
        iocs.add_network_location(
            NetworkLocation(host=cnc["host"], port=cnc.get("port"))
        )
    return iocs


@module("trickbot")
def parse_trickbot(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    # TODO public_key ecdsa_pub_p384
    for cnc in config.get("urls", []):
        iocs.add_network_location(
            NetworkLocation(host=cnc["cnc"], port=cnc["port"])
        )
    return iocs


@module("emotet_upnp")
def parse_emotetupnp(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for cnc in config.get("urls", []):
        iocs.add_network_location(
            NetworkLocation(host=cnc["cnc"], port=cnc["port"])
        )
    return iocs


@module("smokeloader")
def parse_smokeloader(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for cnc in config.get("domains", []):
        iocs.add_network_location(NetworkLocation.parse_url(cnc["cnc"]))
    return iocs


@module("njrat")
def parse_njrat(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for cnc in config.get("c2", []):
        iocs.add_network_location(NetworkLocation(host=cnc))
    if "drop_name" in cnc:
        iocs.add_drop_filename(cnc["drop_name"])
    return iocs


@module("tofsee")
def parse_tofsee(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for cnc in config.get("urls", []):
        iocs.add_network_location(
            NetworkLocation(host=cnc["ip"], port=cnc["port"])
        )
    return iocs
