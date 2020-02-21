from typing import Dict, Any
from .model import RsaKey, IocCollection
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
        iocs.try_add_rsa_from_pem(config["public_key"])
    for url in config.get("urls", []):
        iocs.try_add_network_location(host=url["cnc"], port=url["port"])
    return iocs


@module("emotet_spam")
def parse_emotet_spam(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for url in config.get("urls", []):
        iocs.try_add_network_location(host=url["cnc"], port=url["port"])
    return iocs


@module("emotet_doc")
def parse_emotet_doc(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for url in config.get("urls", []):
        iocs.try_add_url(url)
    return iocs


@module("netwire")
def parse_netwire(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for url in config.get("urls", []):
        iocs.try_add_network_location(host=url["cnc"], port=url["port"])
    if "password" in config:
        iocs.add_password(config["password"])
    if "mutex" in config:
        iocs.add_mutex(str(config["mutex"]))
    return iocs


@module("avemaria")
def parse_avemaria(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for url in config.get("c2", []):
        iocs.try_add_network_location(host=url["host"])
    if "drop_name" in config:
        iocs.add_drop_filename(config["drop_name"])
    return iocs


@module("remcos")
def parse_remcos(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for url in config.get("c2", []):
        ip, portstr = url["host"].split(":")
        iocs.try_add_network_location(host=ip, port=int(portstr))
    return iocs


@module("brushaloader")
def parse_brushaloader(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    if "url" in config:
        iocs.try_add_url(config["url"])
    return iocs


@module("ostap")
def parse_ostap(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for url in config.get("urls", []):
        iocs.try_add_url(url["url"])
    return iocs


@module("wshrat")
def parse_wshrat(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for url in config.get("c2", []):
        if url.count(":") != 1:
            continue
        ip, portstr = url.split(":")
        iocs.try_add_network_location(ip=ip, port=int(portstr))
    return iocs


@module("formbook")
def parse_formbook(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for url in config.get("urls", []):
        iocs.try_add_url(url["url"])
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
        iocs.try_add_url(config["cnc"])
    return iocs


@module("lokibot")
def parse_lokibot(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for url in config.get("urls", []):
        iocs.try_add_url(url["url"])
    return iocs


@module("danaloader")
def parse_danaloader(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for url in config.get("urls", []):
        iocs.try_add_url(url["url"])
    return iocs


@module("evil-pony")
@module("pony")
def parse_evilpony(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for url in config.get("urls", []):
        iocs.try_add_url(url["url"])
    return iocs


@module("quasarrat")
def parse_quasarrat(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for url in config.get("hosts", []):
        iocs.try_add_url(url)

    if "encryption_key" in config:
        iocs.add_password(config["encryption_key"])

    if "install_name" in config:
        iocs.add_drop_filename(config["install_name"])

    if "mutex" in config:
        iocs.add_mutex(str(config["mutex"]))

    return iocs


@module("hawkeye")
def parse_hawkeye(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()

    if "EmailUsername" in config:
        iocs.add_email(config["EmailUsername"])

    if "Mutex" in config:
        iocs.add_mutex(str(config["Mutex"]))

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
        iocs.try_add_network_location(host=domain["cnc"])

    for url in config.get("urls", []):
        iocs.try_add_url(url["url"])
    return iocs


@module("danabot")
def danabot(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    if "rsa_key" in config:
        iocs.try_add_rsa_from_base64(config["rsa_key"])

    for netloc in config.get("urls", []):
        iocs.try_add_network_location(host=netloc)
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
        iocs.try_add_network_location(host=cnc["host"], port=cnc.get("port"))
    return iocs


@module("trickbot")
def parse_trickbot(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    # TODO public_key ecdsa_pub_p384
    for cnc in config.get("urls", []):
        iocs.try_add_network_location(host=cnc["cnc"], port=cnc["port"])
    return iocs


@module("emotet_upnp")
def parse_emotetupnp(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for cnc in config.get("urls", []):
        iocs.try_add_network_location(host=cnc["cnc"], port=cnc["port"])
    return iocs


@module("smokeloader")
def parse_smokeloader(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for cnc in config.get("domains", []):
        iocs.try_add_url(cnc["cnc"])
    return iocs


@module("njrat")
def parse_njrat(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for cnc in config.get("c2", []):
        iocs.try_add_network_location(host=cnc)
    if "drop_name" in config:
        iocs.add_drop_filename(config["drop_name"])
    return iocs


@module("guloader")
def parse_guloader(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    if "url" in config:
        iocs.try_add_url(config["url"])
    if "key" in config:
        iocs.add_key("xor", config["key"])
    return iocs


@module("raccoon")
def parse_raccoon(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for url in config.get("urls", {}).values():
        iocs.try_add_url(url)
    if "rc4_key" in config:
        iocs.add_key("rc4", config["rc4_key"])
    return iocs


@module("kpot")
def parse_kpot(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for url in config.get("url", []):
        iocs.try_add_url(url)
    if "key" in config:
        iocs.add_key("other", config["key"])
    return iocs


@module("icedid")
def parse_icedid(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for domain in config.get("domains", []):
        iocs.try_add_url(domain["cnc"])
    return iocs


@module("zloader")
def parse_zloader(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for domain in config.get("domains", []):
        iocs.try_add_url(domain["cnc"])
    for ip in config.get("ips", []):
        iocs.try_add_url(ip)
    if "key" in config:
        iocs.add_key("other", config["key"])
    if "public_key" in config:
        pk = config["public_key"]
        iocs.add_rsa_key(RsaKey(pk["n"], pk["e"]))
    return iocs


@module("get2")
def parse_get2(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    if "url" in config:
        iocs.try_add_url(config["url"])
    return iocs


@module("ramnit")
def parse_ramnit(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for domain in config.get("hardcoded_domain", []):
        iocs.try_add_url(domain)
    if "rc4_key" in config:
        iocs.add_key("rc4", config["rc4_key"])
    return iocs


@module("systembc")
def parse_systembc(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for domain in config.get("host", []):
        iocs.try_add_url(domain)
    return iocs


@module("kronos")
def parse_kronos(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    if "cnc" in config:
        iocs.try_add_url(config["cnc"])
    for url in config.get("urls", []):
        iocs.try_add_url(url["url"])
    return iocs


@module("kins")
def parse_kins(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    if "aes-key" in config:
        iocs.add_key("aes", config["aes-key"])
    for url in config.get("urls", []):
        iocs.try_add_url(url)
    return iocs


@module("tofsee")
def parse_tofsee(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for cnc in config.get("urls", []):
        iocs.try_add_network_location(host=cnc["ip"], port=cnc["port"])
    return iocs
