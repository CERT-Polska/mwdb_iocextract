# mwdb-iocextract

Python 3 library useful for getting structured IOC data from [mwdb](https://mwdb.cert.pl) configs.

## Why?

_Warning: this project is only relevant to [mwdb](https://mwdb.cert.pl) and [malduck](https://malduck.readthedocs.io) users._

Malduck configs (like the ones in mwdb) are usually unstructured (they're just JSONs with some additional metadata).
On the other hand, automated processing often requires structured data.

For example, URL processing and extraction is a common use case for analysts. Sadly, every module stores them a bit
differently (and due to backward compatibility we're not ready to change that).

For example, compare how we store URLs from ISFB:

```json
"domains": [
    {
        "cnc": "http://fantaniz.ru"
    },
    {
        "cnc": "http://snezhkaie.ru"
    }
]
```

Lokibot:

```json
"urls": [
    {
        "url": "http://hockvvee.com/chief4/five/fre.php"
    },
    {
        "url": "kbfvzoboss.bid/alien/fre.php"
    },
    {
        "url": "alphastand.top/alien/fre.php"
    }
]
```

And mirai:

```json
"cncs": [
    {
        "host": "107.160.244.5",
        "port": 1024
    }
]
```

With mwdb-iocextract you can handle all these (and dozens more) config types in the same way:

```python
from mwdb_iocextract import parse

config_family = "mirai"
config_data = {
    "cncs": [
        {
            "host": "107.160.244.5",
            "port": 1024
        }
    ],
    "table_key": "0xdedefbaf",
    "variant": "OWARI",
    "type": "mirai"
}

iocs = parse(config_family, config_data)
print(iocs.prettyprint())
```

```
> python test.py
NetLoc 107.160.244.5:1024
```

See below for more usage examples.

## Install

```bash
$ pip install mwdb-iocextract
```

You can find the newest version here:

https://pypi.org/project/mwdb-iocextract/

## How does it work

Most configs can be parsed without any change to this library. Standard keys,
like "urls", are automatically recognised and parsed correctly.

Plurality of the key name does not matter. When value is a list, all elements are added separately.
For example both of these are equivalent:

```json
{
    "urls": "127.0.0.1"
}
```
```json
{
    "url": ["127.0.0.1"]
}
```


Right now this library supports:

#### Network Locations

"Network Locations" can be IP, domain, URL, etc. There are many available formats:

```python
    "hosts": [
        "127.0.0.1",  # format 1 - IP
        "http://malware.com",  # format 2 - URL
        { "cnc": "http://malware.com:1337" },  # format 3 - URL in a dict.
        # Allowed keys: "cnc", "url", "ip", "domain", "host" (all handled in the same way)
        { "cnc": "malware.com", "port": 1337 },  # format 4 - domain/port pair

        # NOT allowed: url + port
        # { "cnc": "http://malware.com:1337", "port": 1337 },
```

Config keys: `urls`, `c2`, `ips`, `domains`, `url`, `cnc`, `cncs`, `hosts`, `host`, `cncurl`.

#### Passwords

Passwords hardcoded in malware. Plain text.

Config keys: `password`.

#### Mutexes

Config keys: `mtx`, `mutex`. Plain text.

#### Emails

Emails used by malware and hardcoded in the source. Plain text.

Config keys: `email`, `emails`.

#### Ransom messages

HTML or txt ransom messages hardcoded in the source. Plain text.

Config keys: `ransommessage`.

#### RSA keys

RSA public or private keys hardcoded in the binary.

There are two supported formats:
 - plaintext (`"-----BEGIN PUBLIC KEY-----..."`)
 - parsed - a dict with "n", "e", and (optionall) "d" keys.

Parsed format is more deterministic and recommended for your modules, but you can use both.

Config keys: `publickey`, `rsapub`, `rsakey`, `pubkey`, `privkey`.

#### AES keys

AES keys hardcoded in the binary. Plaintext.

Config keys: `aeskey`.

#### XOR keys

XOR keys hardcoded in the binary. Plaintext.

Config keys: `xorkey`.

#### Serpent keys

XOR keys hardcoded in the binary. Plaintext.

Config keys: `serpentkey`.

#### Encryption keys

Other key types found in the malware. Extracted as a key of type "unknown". Plaintext.

Config keys: `encryptionkey`, `key`, `keys`.

#### Dropped files

Paths or filenames of files dropped by the malware. Plaintext.

Config keys: `drop_name`.


## Contributing

If you want to extend this library or add support for more modules, feel free to
contribute to this repository. We're only interested in modules at least
partially publicly accessible. So [mwcfg.info](http://mwcfg.info/) module
support is OK to merge, but your in-house internal TLP:RED modules - probably
no.

## Usage

### Scan mwdb

How to download config from mwdb and parse it:

```python
from mwdb_iocextract import parse
from mwdblib import Malwarecage


def main():
    # See also https://mwdblib.readthedocs.io/en/latest/index.html
    mwdb = Malwarecage()
    mwdb.login("msm", "my_secret_password")

    for cfg in mwdb.recent_configs():
        if cfg.type != "static":
            # This library only works with configs of type "static" 
            # (default mwdb config type).
            continue
        iocs = parse(cfg.family, cfg.cfg)
        print(iocs.prettyprint())  # convert all IoCs to string


if __name__ == "__main__":
    main()
```

### Working with IOCs

The result of a `parse()` is a `IocCollection` object.
You can use it like a normal Python object, for example:

```python
iocs = parse(cfg.family, cfg.cfg)

for rsa_key in iocs.rsa_keys:
    e = rsa_key.e  # get e
    n = rsa_key.n  # get n

for netloc in iocs.network_locations:
    ip = netloc.ip  # get IP if known
    domain = netloc.domain  # get domain if known
    host = netloc.host  # get domain if known, otherwise IP
    port = netloc.port  # get port if known
    loctype = netloc.location_type  # get type (usually CNC)
    url = netloc.url  # get host + port + path

for key_type, key_data in iocs.keys:
    # key_type - for example "rc4"
    # key_data - hexencoded bytes, for example "6123541243"
    pass

iocs.passwords  # passwords or similar data found in the config
iocs.mutexes  # mutex names used by malware
iocs.dropped_filenames  # filenames dropped on the disk
iocs.emails  # emails used by malware
```

### MISP integration

You can convert `IocCollection` to a MISP object:

```python
def upload_to_misp(family, config):
    iocs = parse(family, config)

    if not iocs:
        # Nothing actionable found - skip the config
        return

    # Be careful not to upload duplicated events.
    # We use uuid5s generated from mwdb dhash as unique deterministic UUIDs.
    event = MISPEvent()
    event.add_tag(f"mwdb:family:{family}")
    event.info = f"Malware configuration ({family})"

    for o in iocs.to_misp():
        event.add_object(o)

    misp = ExpandedPyMISP(MISP_URL, MISP_KEY, MISP_VERIFYCERT)
    misp.add_event(event)
```
