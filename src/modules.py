import string
from base64 import b64decode
from typing import Any, Dict, List

from .errors import ModuleAlreadyRegisteredError
from .model import EcdsaCurve, IocCollection, LocationType, RsaKey

modules: Dict[str, Any] = {}


# Utils


def module(name):
    def decorator(func):
        if name in modules:
            raise ModuleAlreadyRegisteredError()
        modules[name] = func
        return func

    return decorator


def canonicalise(name: str) -> str:
    return name.lower().replace("-", "").replace("_", "")


def safe_get_list(config: Dict[str, Any], key: str) -> List[Any]:
    result = []
    for itkey, elem in config.items():
        if canonicalise(key) != canonicalise(itkey):
            continue
        if not isinstance(elem, list):
            result.append(elem)
        else:
            result += elem
    return result


def add_url(iocs: IocCollection, config: Dict[str, Any], key: str) -> None:
    for domain in safe_get_list(config, key):
        if isinstance(domain, str):
            iocs.try_add_url(domain)
        elif isinstance(domain, dict):
            for hostkey in ["cnc", "url", "ip", "domain", "host"]:
                if hostkey in domain:
                    if "port" in domain:
                        iocs.add_host_port(domain[hostkey], domain["port"])
                    else:
                        iocs.try_add_url(domain[hostkey])
                    break
            else:
                raise NotImplementedError("Can't find a host for the domain")
        else:
            raise NotImplementedError(
                "The domain has to be either a string or a list"
            )


def add_rsa_key(iocs: IocCollection, config: Dict, key: str) -> None:
    for enckey in safe_get_list(config, key):
        if isinstance(enckey, dict):
            if "n" in enckey and "d" in enckey:
                iocs.add_rsa_key(
                    RsaKey(
                        int(enckey["n"]), int(enckey["e"]), int(enckey["d"])
                    )
                )
                continue
            if "n" in enckey:
                iocs.add_rsa_key(RsaKey(int(enckey["n"]), int(enckey["e"])))
                continue
        if isinstance(enckey, list):
            if len(enckey) == 2:
                iocs.add_rsa_key(RsaKey(int(enckey[0]), int(enckey[1])))
                continue
        if isinstance(enckey, str):
            if "BEGIN PUBLIC" in enckey or "BEGIN RSA PUBLIC" in enckey:
                iocs.try_add_rsa_from_pem(enckey)
                continue
        if isinstance(enckey, str) and all(
            c in string.hexdigits for c in enckey
        ):
            enc_bytes = bytes.fromhex(enckey)
            # asn1-encoded public key
            if enc_bytes.startswith(b"\x30\x81\x9f\x30"):
                iocs.try_add_rsa_from_asn1_bytes(enc_bytes.rstrip(b"\x00"))
                continue

        raise NotImplementedError("Unknown RSA key type")


def add_key(iocs: IocCollection, config: Dict, key: str, keytype: str) -> None:
    for enckey in safe_get_list(config, key):
        iocs.add_key(keytype, enckey)


def add_mutex(iocs: IocCollection, config: Dict, key: str) -> None:
    for mutex in safe_get_list(config, key):
        print("mutex", mutex)
        iocs.add_mutex(mutex)


# Generic handlers


def parse(config: Dict[str, Any], iocs: IocCollection) -> None:
    for name in ["publickey", "rsapub", "rsakey", "pubkey", "privkey"]:
        add_rsa_key(iocs, config, name)

    for name in [
        "urls",
        "c2",
        "ips",
        "domains",
        "url",
        "cnc",
        "cncs",
        "hosts",
        "host",
        "cncurl",
        "dropper",
    ]:
        add_url(iocs, config, name)

    if "password" in config:
        iocs.add_password(config["password"])

    for name in ["mutex", "mtx"]:
        for mutex in safe_get_list(config, name):
            iocs.add_mutex(mutex)

    for name in ["email", "emails"]:
        for email in safe_get_list(config, name):
            iocs.add_email_to(email)

    for ransom_message in safe_get_list(config, "ransommessage"):
        iocs.add_ransom_message(ransom_message)

    for name in ["encryptionkey", "key", "keys"]:
        for key in safe_get_list(config, name):
            iocs.add_key("unknown", key)

    for key in safe_get_list(config, "rc4key"):
        iocs.add_key("rc4", key)

    for key in safe_get_list(config, "xorkey"):
        iocs.add_key("xor", key)

    for key in safe_get_list(config, "aeskey"):
        iocs.add_key("aes", key)

    for key in safe_get_list(config, "serpentkey"):
        iocs.add_key("serpent", key)

    for drop in safe_get_list(config, "drop_name"):
        iocs.add_drop_filename(drop)


# CERT.PL modules


@module("netwire")
def parse_netwire(config: Dict[str, Any]) -> IocCollection:
    if "mutex" in config and isinstance(config["mutex"], bool):
        # netwire "mutex" is bool for some reason
        del config["mutex"]
    return IocCollection()


@module("quasarrat")
def parse_quasarrat(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    if "encryption_key" in config:
        iocs.add_password(config["encryption_key"])
        del config["encryption_key"]

    if "install_name" in config:
        iocs.add_drop_filename(config["install_name"])

    return iocs


@module("hawkeye")
def parse_hawkeye(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()

    if config.get("EmailUsername"):
        iocs.add_email_to(config["EmailUsername"])

    return iocs


@module("trickbot")
def parse_trickbot(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    if config.get("public_key"):
        ecdsa = config["public_key"]
        iocs.add_ecdsa_curve(
            EcdsaCurve(ecdsa["t"], int(ecdsa["x"]), int(ecdsa["y"])),
        )
        del config["public_key"]
    return iocs


@module("ramnit")
def parse_ramnit(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for domain in config.get("hardcoded_domain", []):
        iocs.try_add_url(domain)
    return iocs


@module("legionloader")
def parse_legionloader(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    if "stealer" in config:
        iocs.try_add_url(config["stealer"])
    for drop in config.get("drops", []):
        iocs.try_add_url(drop, location_type=LocationType.DOWNLOAD_URL)
    return iocs


@module("panda")
def parse_panda(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    if "comm_public_key" in config:
        if type(config["comm_public_key"]) == str:
            iocs.try_add_rsa_from_pem(config["comm_public_key"])
        elif type(config["comm_public_key"]) == dict:
            key = config["comm_public_key"]
            iocs.add_rsa_key(RsaKey(int(key["n"]), int(key["e"])))
    return iocs


@module("danabot")
def parse_vjworm(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    if "rsa_key" in config:
        iocs.try_add_rsa_from_base64(config["rsa_key"])
        del config["rsa_key"]
    return iocs


@module("nymaim")
def parse_nymaim(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    if "urls" in config:
        for url in config["urls"]:
            url = url.replace("]", "")  # some mistakes cannot be unmade
            iocs.try_add_url(url)
        del config["urls"]
    return iocs


@module("zeus")
def parse_zeus(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    if "rc4sbox" in config:
        iocs.add_key("rc4", config["rc4sbox"])
    return iocs


@module("vmzeus")
def parse_vmzeus(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    if "rc4sbox" in config:
        iocs.add_key("rc4", config["rc4sbox"])
    if "rc6sbox" in config:
        iocs.add_key("rc6", config["rc6sbox"])
    return iocs


@module("sendsafe")
def parse_sendsafe(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    if "cnc" in config and "http_port" in config:
        iocs.add_host_port(config["cnc"], int(config["http_port"]))
        del config["cnc"]
        del config["http_port"]
    return iocs


@module("necurs")
def parse_necurs(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    add_rsa_key(iocs, config, "c2_public_key")
    return iocs


@module("isfb")
def parse_isfb(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    if "key" in config:
        # "key" key is a serpent key
        iocs.add_key("serpent", "key")
        del config["key"]
    return iocs


@module("guloader")
def parse_guloader(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    if "key" in config:
        # "key" key is a xor key
        iocs.add_key("xor", "key")
        del config["key"]
    return iocs


@module("pushdo")
def parse_pushdo(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    if "cfgkey" in config:
        add_rsa_key(iocs, config, "cfgkey")
        del config["cfgkey"]
    return iocs


@module("locky")
def parse_locky(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for payment_domain in config["payment_domain"]:
        iocs.try_add_url(payment_domain)
    return iocs


@module("cerber")
def parse_cerber(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    for dpurl in config.get("default_payment_url", []):
        iocs.try_add_url(dpurl)
    if "global_public_key" in config:
        iocs.try_add_rsa_from_base64(config["global_public_key"])
    return iocs


@module("kbot")
def parse_kbot(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    if "public_key" in config:
        pk = config["public_key"]
        if isinstance(pk, list) and pk and isinstance(pk[-1], int):
            iocs.add_rsa_key(RsaKey(int(pk[0]), int(pk[1])))
            del config["public_key"]
    if "serverpub" in config:
        iocs.add_key("other", config["serverpub"])
    if "botcommunity" in config:
        iocs.add_campaign_id(config["botcommunity"])
    return iocs


@module("alien")
def parse_alien(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()
    add_url(iocs, config, "C2 alt")
    return iocs


@module("lockbit")
def parse_lockbit(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()

    # as far as I can tell, this is a custom format used by lockbit
    if "rsa_pub" in config:
        try:
            key_blob = b64decode(config["rsa_pub"])
            e = int.from_bytes(key_blob[:4], "little")
            n = int.from_bytes(key_blob[128:], "little")

            if e == 0x10001:
                iocs.add_rsa_key(RsaKey(n=n, e=e))
                del config["rsa_pub"]
        except Exception:
            pass

    return iocs


@module("agenttesla")
def parse_agenttesla(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()

    if config.get("email"):
        iocs.add_email_from(config["email"])
        del config["email"]

    if config.get("email_to"):
        iocs.add_email_to(config["email_to"])
        del config["email_to"]

    return iocs


@module("formbook")
def parse_formbook(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()

    if "urls" in config:
        del config["urls"]

    if "c2_url" in config:
        iocs.try_add_url(config["c2_url"])
        del config["c2_url"]

    return iocs


@module("cobaltstrike")
def parse_cobaltstrike(config: Dict[str, Any]) -> IocCollection:
    iocs = IocCollection()

    if config.get("payload_type", "").endswith("stager"):
        for url_row in config.get("stager_url", []):
            url = url_row["url"]
            iocs.try_add_url(url)
    else:
        beacon_type = config.get("beacon_type", [None])[0]
        if beacon_type in ("HTTP", "HTTPS"):
            scheme = beacon_type.lower()
            port = config["port"]
            c2 = config["server,get-uri"].split(",")

            for i in range(0, len(c2), 2):
                hostname, path = c2[i], c2[i + 1]
                iocs.try_add_url(f"{scheme}://{hostname}:{port}{path}")

            del config["urls"]

    return iocs
