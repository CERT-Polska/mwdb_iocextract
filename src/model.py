from typing import List, Optional, Tuple
from Cryptodome.PublicKey import RSA  # type: ignore
from urllib.parse import urlparse
from malduck import base64, rsa  # type: ignore
import re
from enum import Enum
from .errors import NotADomainOrIpError, InvalidNetLocError, IocExtractError
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

    def __init__(self, n: int, e: int) -> None:
        """ Initialise RsaKey instance using n and e parameters directly """
        self.n = n
        self.e = e

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
        return mo

    def prettyprint(self) -> str:
        """ Pretty print for debugging """
        return f"RsaKey n={self.n} e={self.e}"


class NetworkLocation:
    """ Represents a network location. Can be a domain, ip with a port, etc.
    """

    def __init__(
        self,
        location_type: LocationType = LocationType.CNC,
        ip: Optional[str] = None,
        host: Optional[str] = None,
        port: Optional[int] = None,
        path: Optional[str] = None,
    ) -> None:
        """ All fields are optional.
        If specified, `ip` must be a valid ipv4.
        If `ip` is not specified`, `host` can be either ip or domain name.
        if `ip` is specified, `host` must be a domain name or None.
        It's recommended to just specify "host" and let the class decide
        what it is (the only exception is when you know both ip and domain).
        """
        if host is not None and "/" in host:
            raise NotADomainOrIpError()
        self.ip = None
        self.domain = None
        if ip is None:
            if host is None:
                raise InvalidNetLocError("ip or host must be specified")
            if is_ipv4(host):
                self.ip = host
            else:
                self.domain = host
        else:
            if not is_ipv4(ip):
                raise InvalidNetLocError(f"{ip} is not a valid ipv4 address")
            self.ip = ip
            if host is not None:
                if is_ipv4(host):
                    raise InvalidNetLocError(
                        f"when ip is specified, host must be a domain"
                    )
                self.domain = host

        self.port = port
        self.path = path
        self.location_type = location_type

    @classmethod
    def parse_url(cls, url: str) -> "NetworkLocation":
        """ Parse a url (i.e. something like "http://domain.pl:1234/path") """
        try:
            urlobj = urlparse(url)
            if urlobj.hostname is None:
                # probably a missing schema - retry with a fake one
                urlobj = urlparse("http://" + url)
        except ValueError:
            raise InvalidNetLocError(f"{url} is not a valid url.")

        return cls(host=urlobj.hostname, port=urlobj.port, path=urlobj.path)

    def to_misp(self) -> MISPObject:
        obj = MISPObject("url", standalone=False)
        if self.ip:
            a = obj.add_attribute("ip", self.ip)
            a.add_tag(f"mwdb:location_type:{self.location_type.value}")
        if self.domain:
            a = obj.add_attribute("domain", self.domain)
            a.add_tag(f"mwdb:location_type:{self.location_type.value}")
        if self.port:
            obj.add_attribute("port", self.port)
        if self.path:
            obj.add_attribute("resource_path", self.path)
        return obj

    def prettyprint(self) -> str:
        """ Pretty print for debugging """
        loc = ""
        if self.ip is not None:
            if self.domain is not None:
                loc = f"[{self.domain}={self.ip}]"
            else:
                loc = self.ip
        else:
            loc = str(self.domain)
        if self.port is not None:
            loc += ":" + str(self.port)
        if self.path is not None:
            loc += "/" + self.path

        return f"NetLoc " + loc


class IocCollection:
    """ Represents a collection of parsed IoCs """

    def __init__(self) -> None:
        """ Creates an empty IocCollection instance """
        self.rsa_keys: List[RsaKey] = []
        self.keys: List[Tuple[str, str]] = []  # (keytype, hexencoded key)
        self.passwords: List[str] = []
        self.network_locations: List[NetworkLocation] = []
        self.mutexes: List[str] = []
        self.dropped_filenames: List[str] = []
        self.emails: List[str] = []

    def add_rsa_key(self, rsakey: RsaKey) -> None:
        self.rsa_keys.append(rsakey)

    def add_key(self, key_type: str, xor_key: str) -> None:
        """ Add a hex encoded other raw key - for example, xor key """
        self.keys.append((key_type, xor_key))

    def try_add_rsa_from_pem(self, pem: str) -> None:
        try:
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

    def try_add_network_location(
        self,
        location_type: LocationType = LocationType.CNC,
        ip: Optional[str] = None,
        host: Optional[str] = None,
        port: Optional[int] = None,
        path: Optional[str] = None,
    ) -> None:
        try:
            self.add_network_location(
                NetworkLocation(
                    location_type=location_type,
                    ip=ip,
                    host=host,
                    port=port,
                    path=path,
                )
            )
        except IocExtractError:
            pass

    def try_add_url(self, url: str) -> None:
        try:
            self.network_locations.append(NetworkLocation.parse_url(url))
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

    def to_misp(self) -> List[MISPObject]:
        """MISP JSON output"""
        to_return = []
        for rsa_key in self.rsa_keys:
            to_return.append(rsa_key.to_misp())
        for netloc in self.network_locations:
            to_return.append(netloc.to_misp())
        # TODO passwords
        # TODO mutexes
        # TODO drops
        # TODO emails
        return to_return

    def prettyprint(self) -> str:
        """ Pretty print for debugging """
        result = []
        for rsa_key in self.rsa_keys:
            result.append(rsa_key.prettyprint())
        for netloc in self.network_locations:
            result.append(netloc.prettyprint())
        for password in self.passwords:
            result.append("Password " + password)
        for mutex in self.mutexes:
            result.append("Mutex " + mutex)
        for drop_filename in self.dropped_filenames:
            result.append("Drop " + drop_filename)
        for email in self.emails:
            result.append("Email " + email)
        for key_type, key_data in self.keys:
            result.append(f"Key {key_type}:{key_data}")
        return "\n".join(result)

    def __bool__(self) -> bool:
        return any(
            [
                self.rsa_keys,
                self.passwords,
                self.network_locations,
                self.mutexes,
                self.dropped_filenames,
            ]
        )
