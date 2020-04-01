from typing import Dict, Any
from .model import LocationType, RsaKey, EcdsaCurve, IocCollection
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
        iocs.add_host_port(url["cnc"], url["port"])
    return iocs


@module("emotet_spam")
def parse_emotet_spam(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for url in config.get("urls", []):
        iocs.add_host_port(url["cnc"], url["port"])
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
        iocs.add_host_port(url["cnc"], url["port"])
    if "password" in config:
        iocs.add_password(config["password"])
    if "mutex" in config:
        iocs.add_mutex(str(config["mutex"]))
    return iocs


@module("avemaria")
def parse_avemaria(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for url in config.get("c2", []):
        iocs.try_add_url(url["host"])
    if "drop_name" in config:
        iocs.add_drop_filename(config["drop_name"])
    return iocs


@module("remcos")
def parse_remcos(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for url in config.get("c2", []):
        ip, portstr = url["host"].split(":")
        iocs.add_host_port(ip, int(portstr))
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
        iocs.try_add_url(url)
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

    if config.get("EmailUsername"):
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
        iocs.add_rsa_key(RsaKey(int(pk["n"]), int(pk["e"])))

    for domain in config.get("domains", []):
        # TODO: what about fake domains here?
        iocs.try_add_url(domain["cnc"])

    for url in config.get("urls", []):
        iocs.try_add_url(url["url"])
    return iocs


@module("danabot")
def danabot(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    if "rsa_key" in config:
        iocs.try_add_rsa_from_base64(config["rsa_key"])

    for netloc in config.get("urls", []):
        iocs.try_add_url(netloc)
    return iocs


@module("nanocore")
@module("orcusrat")
@module("testmod")
@module("qakbot")
@module("sodinokibi")
@module("citadel")
@module("madness_pro")
@module("onliner")
@module("unknown")
@module("tinba")
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
        iocs.add_host_port(cnc["host"], cnc.get("port"))
    return iocs


@module("trickbot")
def parse_trickbot(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    if config["public_key"]:
        ecdsa = config["public_key"]
        iocs.add_ecdsa_curve(
            EcdsaCurve(ecdsa["t"], int(ecdsa["x"]), int(ecdsa["y"])),
        )
    for cnc in config.get("urls", []):
        iocs.add_host_port(cnc["cnc"], cnc["port"])
    return iocs


@module("emotet_upnp")
def parse_emotetupnp(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for cnc in config.get("urls", []):
        iocs.add_host_port(cnc["cnc"], cnc["port"])
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
        iocs.try_add_url(cnc)
    if "drop_name" in config:
        iocs.add_drop_filename(config["drop_name"])
    return iocs


@module("guloader")
def parse_guloader(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    if "url" in config:
        iocs.try_add_url(config["url"])
    for url in config.get("urls", []):
        iocs.try_add_url(url["url"])
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
        iocs.add_rsa_key(RsaKey(int(pk["n"]), int(pk["e"])))
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
        iocs.add_host_port(cnc["ip"], cnc["port"])
    return iocs


@module("elknot")
def parse_elknot(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for cnc in config.get("cncs", []):
        if "host" not in cnc:
            continue
        iocs.add_host_port(cnc["host"], cnc.get("port"))
    return iocs


@module("legionloader")
def parse_legionloader(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    if "cnc" in config:
        iocs.try_add_url(config["cnc"])
    if "stealer" in config:
        iocs.try_add_url(config["stealer"])
    for drop in config.get("drops", []):
        iocs.try_add_url(drop, location_type=LocationType.DOWNLOAD_URL)
    return iocs


@module("dridex")
def parse_dridex(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for c2 in config.get("c2", []):
        iocs.try_add_url(c2)
    for key in config.get("RC4_key", []):
        iocs.add_key("rc4", key)
    return iocs


@module("phorpiex")
def parse_phorpiex(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    if "cnc_url" in config:
        iocs.try_add_url(config["cnc_url"])
    for cnc in config.get("cncs", []):
        iocs.add_host_port(cnc["host"], cnc.get("port"))
    if "encryption_key" in config:
        iocs.add_key("other", config["encryption_key"])
    return iocs


@module("pushdo")
def parse_pushdo(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    if "cfgkey" in config:
        key = config["cfgkey"]
        iocs.add_rsa_key(RsaKey(int(key["n"]), int(key["e"]), int(key["d"])))
    if "privkey" in config:
        key = config["privkey"]
        iocs.add_rsa_key(RsaKey(int(key["n"]), int(key["e"]), int(key["d"])))
    if "pubkey" in config:
        key = config["pubkey"]
        iocs.add_rsa_key(RsaKey(int(key["n"]), int(key["e"])))
    # ignore "domains", because of tons of false positives
    return iocs


@module("panda")
def parse_panda(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for cnc in config.get("cnc", []):
        iocs.try_add_url(cnc["url"])
    if "comm_public_key" in config:
        if type(config["comm_public_key"]) == str:
            iocs.try_add_rsa_from_pem(config["comm_public_key"])
        elif type(config["comm_public_key"]) == dict:
            key = config["comm_public_key"]
            iocs.add_rsa_key(RsaKey(int(key["n"]), int(key["e"])))

    if "public_key" in config:
        if type(config["public_key"]) == str:
            iocs.try_add_rsa_from_pem(config["public_key"])
        elif type(config["public_key"]) == dict:
            key = config["public_key"]
            iocs.add_rsa_key(RsaKey(int(key["n"]), int(key["e"])))

    return iocs


@module("vjworm")
def parse_vjworm(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for urls in config.get("urls", []):
        iocs.try_add_url(urls["url"])
    return iocs


@module("nymaim")
def parse_nymaim(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    if "encryption_key" in config:
        iocs.add_key("other", config["encryption_key"])
    if "public_key" in config:
        key = config["public_key"]
        iocs.add_rsa_key(RsaKey(int(key["n"]), int(key["e"])))
    for url in config["urls"]:
        url = url.replace("]", "")  # some mistakes cannot be unmade
        iocs.try_add_url(url)
    return iocs


@module("globeimposter")
def parse_globeimposter(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for email in config.get("emails", []):
        iocs.add_email(email)
    if "ransom_message" in config:
        iocs.add_ransom_message(config["ransom_message"])
    for url in config.get("urls", []):
        iocs.try_add_url(url)
    return iocs


@module("gootkit")
def parse_gootkit(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for domain in config.get("domains", []):
        iocs.try_add_url(domain["cnc"])
    return iocs


@module("hancitor")
def parse_hancitor(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for urls in config.get("urls", []):
        iocs.try_add_url(urls["url"])
    return iocs


@module("zeus")
def parse_zeus(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    if "rc4sbox" in config:
        iocs.add_key("rc4", config["rc4sbox"])
    if "cnc" in config:
        iocs.try_add_url(config["cnc"])
    for url in config.get("urls", []):
        iocs.try_add_url(url)
    return iocs


@module("vmzeus")
def parse_vmzeus(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    if "rc4sbox" in config:
        iocs.add_key("rc4", config["rc4sbox"])
    if "rc6sbox" in config:
        iocs.add_key("rc6", config["rc6sbox"])
    for url in config.get("urls", []):
        iocs.try_add_url(url)
    return iocs


@module("sendsafe")
def parse_sendsafe(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    if "cnc" in config and "http_port" in config:
        iocs.add_host_port(config["cnc"], int(config["http_port"]))
    return iocs


@module("necurs")
def parse_necurs(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for domain in config.get("domains", []):
        iocs.try_add_url(domain["cnc"])
    if "c2_public_key" in config:
        key = config["c2_public_key"]
        if type(key) == dict:
            iocs.add_rsa_key(RsaKey(int(key["n"]), int(key["e"])))
        elif type(key) == str:
            iocs.try_add_rsa_from_pem(config["c2_public_key"])
    if "mutex" in config:
        iocs.add_mutex(str(config["mutex"]))
    return iocs


@module("troldesh")
def parse_troldesh(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    if "url" in config:
        iocs.try_add_url(config["url"])
    return iocs


@module("xagent")
def parse_xagent(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for url in config.get("urls", []):
        iocs.try_add_url(url)
    return iocs


@module("gluedropper")
def parse_gluedropper(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for domain in config.get("host", []):
        iocs.try_add_url(domain)
    return iocs


@module("neutrino")
def parse_neutrino(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for url in config.get("urls", []):
        iocs.try_add_url(url)
    return iocs


@module("locky")
def parse_locky(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for domain in config.get("domains", []):
        iocs.try_add_url(domain["cnc"])
    for payment_domain in config["payment_domain"]:
        iocs.try_add_url(payment_domain)
    if "public_key" in config:
        key = config["public_key"]
        iocs.add_rsa_key(RsaKey(int(key["n"]), int(key["e"])))
    return iocs


@module("kovter")
def parse_kovter(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    if "public_key" in config:
        key = config["public_key"]
        iocs.add_rsa_key(RsaKey(int(key["n"]), int(key["e"])))
    for url in config.get("urls", []):
        iocs.add_host_port(url["cnc"], int(url["port"]))
    if "rc4key" in config:
        iocs.add_key("rc4", config["rc4key"])
    return iocs


@module("cerber")
def parse_cerber(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for dpurl in config.get("default_payment_url", []):
        iocs.try_add_url(dpurl)
    if "global_public_key" in config:
        iocs.try_add_rsa_from_base64(config["global_public_key"])
    return iocs


@module("quantloader")
def parse_quentloader(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for url in config.get("urls", []):
        iocs.try_add_url(url["url"])
    if "key" in config:
        iocs.add_key("other", config["key"])
    return iocs


@module("kbot")
def parse_kbot(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for domain in config.get("domains", []):
        iocs.try_add_url(domain["cnc"])
    if "serverpub" in config:
        iocs.add_key("other", config["serverpub"])
    if "botcommunity" in config:
        iocs.add_campaign_id(config["botcommunity"])
    return iocs


@module("chthonic")
def parse_chthonic(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for url in config.get("urls", []):
        iocs.try_add_url(url)
    return iocs


@module("retefe")
def parse_retefe(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for url in config.get("urls", []):
        iocs.try_add_url(url)
    return iocs


@module("gandcrab")
def parse_gandcrab(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for domain in config.get("domains", []):
        iocs.try_add_url(domain["cnc"])
    return iocs
