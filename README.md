# mwdb-iocextract

Python 3 library useful for getting structured IOC data from [mwdb](https://mwdb.cert.pl) configs.

## Why?

_Warning: this project is only relevant to [mwdb](https://mwdb.cert.pl) users. Mwdb is our solution for storing and extracting malware. If you're a white-hat security researcher interested in getting access to it, send a request via our website or email `info@cert.pl`._

Mwdb configs are pretty unstructured (they're basically JSONs with some additional metadata). On the other hand, automated processing often requires structured data.

For example, extracting and processing URLs is a common use case for analysts. Sadly, every module stores them a bit differently (and due to backward compatibility we're not ready to change that).

For example, compare how ISFB module reports its URls:

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

## Info

**Contact email**: msm@cert.pl or info@cert.pl

## Install

```bash
$ pip install mwdb-iocextract
```

You can always find the newest version here:

https://pypi.org/project/mwdb-iocextract/

## Usage

### Scan mwdb

In a typical use case, you'll probably want to get and parse configs
downloaded directly from mwdb. To access the mwdb api and download
recent configs we utilise the
[mwdblib](https://github.com/CERT-Polska/mwdblib) (our official API
bindings for [mwdb](mwdb.cert.pl)]).

```python
from mwdb_iocextract import parse
from mwdblib import Malwarecage


def main():
    # See also https://mwdblib.readthedocs.io/en/latest/index.html
    mwdb = Malwarecage()
    mwdb.login("msm", "my_secret_password")

    for cfg in mwdb.recent_configs():
        if cfg.type != "static":
            # Not all configs are created equal.
            # This code only deals with "static" configs, i.e. configs
            # extracted from malware/memory dumps
            continue
        try:
            iocs = parse(cfg.family, cfg.cfg)
        except FamilyNotSupportedYetError:
            # This means, that your mwdb_iocextract version does not
            # support this family. Consider updating it (it may take
            # us a few days to add support for a new family)
            continue
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
def upload_to_misp(family, config)
    try:
        iocs = parse(family, config)
    except FamilyNotSupportedYetError:
        return

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

_Alternatively, depending on who you represent, you can reach out to us and we can discuss sharing our MISP with you._
