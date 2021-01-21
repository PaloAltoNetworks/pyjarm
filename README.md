# pyJARM

[![Latest version released on PyPi](https://img.shields.io/pypi/v/pyjarm.svg)](https://pypi.python.org/pypi/pyjarm)
[![License](https://img.shields.io/pypi/l/pyjarm)](https://github.com/PaloAltoNetworks/pyjarm/blob/main/LICENSE)
[![Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

## Overview

![pyjarm-full](https://user-images.githubusercontent.com/7642165/105419213-9f94f800-5c3e-11eb-80d2-df1a7fdab655.png)

pyJARM is a convenience library for the JARM fingerprinting tool. This library is based on the original python implementation [here](https://github.com/salesforce/jarm).

## Installation
```
pip install pyjarm
```

## Usage

### Command Line
```
usage: jarm [-h] [-i INPUT] [-d] [-o OUTPUT] [-4] [-6] [-c [CONCURRENCY]] [--proxy PROXY]
                   [--proxy-auth PROXY_AUTH] [--proxy-insecure]
                   [scan]

Enter an IP address/domain and port to scan or supply an input file.

positional arguments:
  scan                  Enter an IP or domain to scan.

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Provide a list of IP addresses or domains to scan, one domain or IP address per line. Ports
                        can be specified with a colon (ex. 8.8.8.8:8443)
  -d, --debug           [OPTIONAL] Debug mode: Displays additional debug details
  -o OUTPUT, --output OUTPUT
                        [OPTIONAL] Provide a filename to output/append results to a CSV file.
  -4, --ipv4only        [OPTIONAL] Use only IPv4 connections (incompatible with --ipv6only).
  -6, --ipv6only        [OPTIONAL] Use only IPv6 connections (incompatible with --ipv4only).
  -c [CONCURRENCY], --concurrency [CONCURRENCY]
                        [OPTIONAL] Number of concurrent connections (default is 2).
  --proxy PROXY         [OPTIONAL] Use proxy (format http[s]://user:pass@proxy:port). HTTPS_PROXY env variable is used
                        by default if this is not set. Set this to 'ignore' to ignore HTTPS_PROXY and use no proxy.
  --proxy-auth PROXY_AUTH
                        [OPTIONAL] Send this header in Proxy-Authorization (when using proxy).
  --proxy-insecure      [OPTIONAL] Do not verify SSL_CERTIFICATES (only when HTTPS proxy is set).
```

**Example**
```
$ python jarm google.com
Target: google.com:443
JARM: 27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d
```

### Scripted
```
from jarm.scanner.scanner import Scanner

print(Scanner.scan("google.com", 443))
('27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d', 'google.com', 443)
```

## Contributors

- Andrew Scott - [andrew-paloalto](https://github.com/andrew-paloalto)
- Francesco Vigo - [fvigo](https://github.com/fvigo)
  