# pyJARM

## Overview
pyJARM is a convenience library for the JARM fingerprinting tool. This library is based on the original python implementation [here](https://github.com/salesforce/jarm).

## Installation
```
pip install pyjarm
```

## Usage

### Command Line
```
usage: jarm [-h] [-i INPUT] [-d] [-o OUTPUT] [scan]

Enter an IP address/domain and port to scan or supply an input file.

positional arguments:
  scan                  Enter an IP or domain to scan.

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Provide a list of IP addresses or domains to scan, one
                        domain or IP address per line. Ports can be specified
                        with a colon (ex. 8.8.8.8:8443
  -d, --debug           [OPTIONAL] Debug mode: Displays additional debug
                        details
  -o OUTPUT, --output OUTPUT
                        [OPTIONAL] Provide a filename to output/append results
                        to a CSV file.
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
