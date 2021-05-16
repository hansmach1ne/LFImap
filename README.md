# lfimap
## Local file inclusion discovery and exploitation tool


### lfimap is program for testing Local File Inclusions in web applications



## Install

```
git clone https://github.com/hansmach1ne/lfimap.git
cd lfimap/
pip3 install -r requirements.txt
./lfimap.py -h
```

## Usage

```

usage: ./lfimap.py [--test-php-filter] [--test-php-input] [--test-data] [--test-expect] [-a] [-c <cookie>]
                 [-w <wordlist>] [-h]
                 URL

lfimap, tool for discovering LFI

positional arguments:
  URL                            Url, Ex: "http://example.org/vuln.php?param=DESTROY"

optional arguments:
  --test-php-filter              Test php filter
  --test-php-input               Test php input
  --test-data                    Test data wrapper
  --test-expect                  Test expect wrapper
  -a, --test-all                 Test all above + using wordlist
  -c <cookie>                    Session Cookie, Ex: "PHPSESSID=1943785348b45"
  -w <wordlist>                  Custom wordlist (default wordlist.txt)
  -h, --help                     Print this help message
  
```
