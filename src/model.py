from typing import List, Tuple, Union
from Cryptodome.PublicKey import RSA  # type: ignore
from urllib.parse import urlparse
from malduck import base64, rsa  # type: ignore
import re
from enum import Enum
from .errors import IocExtractError
from pymisp import MISPObject  # type: ignore


def is_ipv4(possible_ip: str):
    """ Very simple heuristics to distinguish IPs from domains """
    return re.match(
        "^[0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}$", possible_ip
    )


class LocationType(Enum):
    """ Type of malicious URL. Not all URLs in malware have the
    same role, and often it's necessary to treat them differently. """

    # C&C server, usually administrated by criminals. Malware connects to
    # it (usually with a custom protocol) to get new commands and updates.
    CNC = "cnc"
    # Download url. Used to download more malware samples. Sometimes just a
    # hacked legitimate website.
    DOWNLOAD_URL = "download_url"
    # Malware panel. HTTP service used by criminals to manage the botnet.
    PANEL = "panel"
    # Peer. IP/port of infected machine of a legitimate computer user.
    PEER = "peer"
    # Other kind of URL found in the malware.
    OTHER = "other"


class RsaKey:
    """ Represents a RSA public key used by malware"""

    def __init__(self, n: int, e: int, d: int = None) -> None:
        """ Initialise RsaKey instance using n and e parameters directly """
        self.n = n
        self.e = e
        self.d = d

    @classmethod
    def parse_pem(cls, pem: str) -> "RsaKey":
        """ Parse PEM ("-----BEGIN PUBLIC KEY" header) key """
        key = RSA.import_key(pem)
        return cls(key.n, key.e)

    @classmethod
    def parse_base64(cls, b64: str) -> "RsaKey":
        """ Parse raw base64 key (used by danabot for example) """
        blob = base64.decode(b64)
        key = rsa.import_key(blob)
        return cls.parse_pem(key)

    def to_misp(self) -> MISPObject:
        mo = MISPObject("crypto-material", standalone=False)
        mo.add_attribute("type", "RSA")
        mo.add_attribute("origin", "malware-extraction")
        mo.add_attribute("modulus", hex(self.n)[2:])
        mo.add_attribute("e", self.e)
        if self.d is not None:
            mo.add_attribute("d", self.d)
        return mo

    def prettyprint(self) -> str:
        """ Pretty print for debugging """
        d_part = f" d={self.d}" if self.d else ""
        return f"RsaKey n={self.n} e={self.e}{d_part}"


class EcdsaCurve:
    """ Represents a ECDSA curve used by malware"""

    def __init__(self, t: str, x: int, y: int) -> None:
        self.t = t
        self.x = x
        self.y = y

    def to_misp(self) -> MISPObject:
        co = MISPObject("crypto-material", standalone=False)
        co.add_attribute("type", "ECDSA")
        if self.t == "ecdsa_pub_p384":
            co.add_attribute("ecdsa-type", "NIST P-384")
        else:
            co.add_attribute("ecdsa-type", self.t)
        co.add_attribute("x", self.x)
        co.add_attribute("y", self.y)
        return co

    def prettyprint(self) -> str:
        return f"EcdsaCurve t={self.t} x={str(self.x)} y={str(self.y)}"


class NetworkLocation:
    """ Represents a network location. Can be a domain, ip with a port, etc.
    """

    def __init__(
        self, url: str, location_type: LocationType = LocationType.CNC
    ) -> None:
        self.url = urlparse(url)
        if self.url.hostname is None:
            self.url = urlparse("unknown://" + url)

        self.location_type = location_type

    @property
    def ip(self):
        if self.url.hostname and is_ipv4(self.url.hostname):
            return self.url.hostname
        return None

    @property
    def domain(self):
        if self.url.hostname and not is_ipv4(self.url.hostname):
            return self.url.hostname
        return None

    @property
    def port(self):
        return self.url.port

    @property
    def path(self):
        return self.url.path

    @property
    def pretty_url(self):
        url = self.url.geturl()
        if url.startswith("unknown://"):
            return url[len("unknown://") :]
        return url

    def to_misp(self) -> MISPObject:
        obj = MISPObject("url", standalone=False)
        obj.add_attribute("url", self.pretty_url)
        if self.ip:
            a = obj.add_attribute("ip", self.ip)
            if a is not None:
                a.add_tag(f"mwdb:location_type:{self.location_type.value}")
        if self.domain:
            a = obj.add_attribute("domain", self.domain)
            if a is not None:
                a.add_tag(f"mwdb:location_type:{self.location_type.value}")
        if self.port:
            obj.add_attribute("port", self.port)
        if self.path:
            obj.add_attribute("resource_path", self.path)
        if self.url.query:
            obj.add_attribute("query_string", self.url.query)
        return obj

    def prettyprint(self) -> str:
        """ Pretty print for debugging """
        return f"NetLoc " + self.pretty_url


class IocCollection:
    """ Represents a collection of parsed IoCs """

    def __init__(self) -> None:
        """ Creates an empty IocCollection instance """
        self.rsa_keys: List[RsaKey] = []
        self.ecdsa_curves: List[EcdsaCurve] = []
        self.keys: List[Tuple[str, str]] = []  # (keytype, hexencoded key)
        self.passwords: List[str] = []
        self.network_locations: List[NetworkLocation] = []
        self.mutexes: List[str] = []
        self.dropped_filenames: List[str] = []
        self.emails: List[str] = []
        self.ransom_messages: List[str] = []
        self.campaign_ids: List[str] = []

    def add_rsa_key(self, rsakey: RsaKey) -> None:
        self.rsa_keys.append(rsakey)

    def add_ecdsa_curve(self, ecdsa_curve: EcdsaCurve) -> None:
        self.ecdsa_curves.append(ecdsa_curve)

    def add_key(self, key_type: str, xor_key: str) -> None:
        """ Add a hex encoded other raw key - for example, xor key """
        self.keys.append((key_type, xor_key))

    def try_add_rsa_from_pem(self, pem: str) -> None:
        try:
            if pem:
                self.add_rsa_key(RsaKey.parse_pem(pem))
        except IocExtractError:
            pass

    def try_add_rsa_from_base64(self, pem: str) -> None:
        try:
            self.add_rsa_key(RsaKey.parse_base64(pem))
        except IocExtractError:
            pass

    def add_network_location(self, netloc: NetworkLocation) -> None:
        self.network_locations.append(netloc)

    def add_host_port(
        self, host: str, port: Union[str, int], schema: str = "unknown"
    ) -> None:
        if isinstance(port, str):
            port_val = int(port)
        else:
            port_val = port
        try:
            self.try_add_url(f"{schema}://{host}:{port_val}")
        except IocExtractError:
            pass

    def try_add_url(
        self, url: str, location_type: LocationType = LocationType.CNC
    ) -> None:
        if not url.strip():
            return
        try:
            self.network_locations.append(
                NetworkLocation(url, location_type=location_type)
            )
        except IocExtractError:
            pass

    def add_password(self, password: str) -> None:
        self.passwords.append(password)

    def add_drop_filename(self, filename: str) -> None:
        self.dropped_filenames.append(filename)

    def add_mutex(self, mutex: str) -> None:
        self.mutexes.append(mutex)

    def add_email(self, email: str) -> None:
        self.emails.append(email)

    def add_ransom_message(self, ransom_message: str) -> None:
        self.ransom_messages.append(ransom_message)

    def add_campaign_id(self, campaign_id: str) -> None:
        self.campaign_ids.append(campaign_id)

    def to_misp(self) -> List[MISPObject]:
        """MISP JSON output"""
        to_return = []
        for rsa_key in self.rsa_keys:
            to_return.append(rsa_key.to_misp())
        for ecdsa_curve in self.ecdsa_curves:
            to_return.append(ecdsa_curve.to_misp())
        if self.keys:
            crypto_obj = MISPObject("crypto-material", standalone=False)
            for k in self.keys:
                crypto_obj.add_attribute("type", k[0])
                crypto_obj.add_attribute("generic-symmetric-key", k[1])
                to_return.append(crypto_obj)
        if self.passwords:
            credential_obj = MISPObject("credential", standalone=False)
            for password in self.passwords:
                credential_obj.add_attribute("password", password)
                to_return.append(credential_obj)
        if self.mutexes:
            mutex_obj = MISPObject("mutex", standalone=False)
            for mutex in self.mutexes:
                mutex_obj.add_attribute("name", mutex)
                to_return.append(mutex_obj)
        for netloc in self.network_locations:
            to_return.append(netloc.to_misp())
        # TODO self.dropped_filenames
        for email in self.emails:
            obj = MISPObject("email", standalone=False)
            obj.add_attribute("to", email)
            to_return.append(obj)

        return to_return

    def prettyprint(self) -> str:
        """ Pretty print for debugging """
        result = []
        for rsa_key in self.rsa_keys:
            result.append(rsa_key.prettyprint())
        for ecdsa_curve in self.ecdsa_curves:
            result.append(ecdsa_curve.prettyprint())
        for key_type, key_data in self.keys:
            result.append(f"Key {key_type}:{key_data}")
        for password in self.passwords:
            result.append("Password " + password)
        for netloc in self.network_locations:
            result.append(netloc.prettyprint())
        for mutex in self.mutexes:
            result.append("Mutex " + mutex)
        for drop_filename in self.dropped_filenames:
            result.append("Drop " + drop_filename)
        for email in self.emails:
            result.append("Email " + email)
        for ransom_message in self.ransom_messages:
            result.append("RansomMessage: " + ransom_message)
        for campaign_id in self.campaign_ids:
            result.append("CampaignId: " + campaign_id)
        return "\n".join(result)

    def __bool__(self) -> bool:
        return any(
            [
                self.rsa_keys,
                self.keys,
                self.passwords,
                self.network_locations,
                self.mutexes,
                self.dropped_filenames,
                self.emails,
                self.ransom_messages,
                self.campaign_ids,
            ]
        )
