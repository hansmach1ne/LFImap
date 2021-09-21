# lfimap
## Local file inclusion discovery and exploitation tool


## Install

```
git clone https://github.com/hansmach1ne/lfimap.git
cd lfimap/
pip3 install -r requirements.txt
python3 lfimap.py -h

```

## Usage

```

usage: lfimap.py [-c <cookie>] [-p <proxy>] [-w <wordlist>] [--useragent <agent>] [--referer <referer>] [--param <name>] [--no-stop] [-f] [-i] [-d] [-e] [-t] [-r] [-a] [-x] [--lhost <lhost>]
                 [--lport <lport>] [-v] [-h]
                 URL

lfimap, Local File Inclusion discovery and exploitation tool

MANDATORY:
  URL                            Specify url, Ex: "http://example.org/vuln.php?param=PWN" 

GENERAL:
  -c <cookie>                    Specify session cookie, Ex: "PHPSESSID=1943785348b45"
  -p <proxy>                     Specify Proxy IP address. Ex: '10.10.10.10:8080'
  -w <wordlist>                  Specify wordlist for truncation attack (default 'short.txt')
  --useragent <agent>            Specify HTTP user agent
  --referer <referer>            Specify HTTP referer
  --param <name>                 Specify parameter name (default 'PWN')
  --no-stop                      Don't stop using same method upon findings

ATTACK TECHNIQUE:
  -f, --php-filter               Attack using php filter wrapper
  -i, --php-input                Attack using php input wrapper
  -d, --php-data                 Attack using php data wrapper
  -e, --php-expect               Attack using php expect wrapper
  -t, --path-trunc               Path truncation attack
  -r, --rfi                      Attack using remote file inclusion
  -a, --attack-all               Use all available methods to attack

PAYLOAD:
  -x, --send-revshell            Send reverse shell connection if possible (Setup reverse handler first)
  --lhost <lhost>                Specify localhost IP address for reverse connection
  --lport <lport>                Specify local PORT number for reverse connection

OTHER:
  -v, --verbose                  Print more detailed output when performing attacks
  -h, --help                     Print this help message


```
