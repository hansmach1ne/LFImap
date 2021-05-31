# lfimap
## Local file inclusion discovery tool


## Install

```
git clone https://github.com/hansmach1ne/lfimap.git
cd lfimap/
pip3 install -r requirements.txt
python3 lfimap.py -h

```
#Currently reverse shell functionality is working with data,expect and input wrappers on LINUX only, in future windows support will be added

#Also, I plan to implement exploitation with different reverse shell types (bash, python, php and more...)


## Usage

```

usage: lfimap.py [-c <cookie>] [-p <proxy>] [--useragent <agent>] [--referer <referer>] [--php-filter] [--php-input] [--php-data] [--php-expect] [--rfi] [-w <wordlist>] [-a] [--send-revshell] [--lhost <lhost>] [--lport <lport>] [-v]
                 [-h]
                 URL

lfimap, LFI discovery and exploitation tool

GENERAL:
  URL                            Specify url, Ex: "http://example.org/vuln.php?param=DESTROY" 
  -c <cookie>                    Specify session cookie, Ex: "PHPSESSID=1943785348b45"
  -p <proxy>                     Specify Proxy IP address. Ex: '10.10.10.10:8080'
  --useragent <agent>            Specify HTTP user agent
  --referer <referer>            Specify HTTP referer

ATTACK TECHNIQUE:
  --php-filter                   Attack using php filter wrapper
  --php-input                    Attack using php input wrapper
  --php-data                     Attack using php data wrapper
  --php-expect                   Attack using php expect wrapper
  --rfi                          Attack using remote file inclusion
  -w <wordlist>                  Specify wordlist for truncation attack
  -a, --attack-all               Use all available methods to attack

PAYLOAD:
  --send-revshell                Send reverse shell connection if possible (Setup reverse handler first.)
  --lhost <lhost>                Specify localhost IP address for reverse connection
  --lport <lport>                Specify local PORT number for reverse connection

OTHER:
  -v, --verbose                  Verbose output
  -h, --help                     Print this help message
  
```
