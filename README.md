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
usage: lfimap.py [-c <cookie>] [-p <proxy>] [-w <wordlist>] [--useragent <agent>] [--referer <referer>] [--param <name>] [--no-stop] [-f] [-i] [-d] [-e] [-t] [-r] [-a] [-x]
                 [--lhost <lhost>] [--lport <lport>] [-v] [-h]
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
  -f, --filter                   Attack using filter:// wrapper
  -i, --input                    Attack using input:// wrapper
  -d, --data                     Attack using data:// wrapper
  -e, --expect                   Attack using expect:// wrapper
  -t, --trunc                    Attack using path truncation with wordlist (default 'short.txt')
  -r, --rfi                      Attack using remote file inclusion
  -a, --attack-all               Use all available methods to attack

PAYLOAD:
  -x, --send-revshell            Send reverse shell if possible (Setup reverse handler first)
  --lhost <lhost>                Specify localhost IP address for reverse connection
  --lport <lport>                Specify local PORT number for reverse connection

OTHER:
  -v, --verbose                  Print more detailed output when performing attacks
  -h, --help                     Print this help message

```


[!] Disclaimer: Lfimap usage for attacking web applications without consent of the application owner is illegal. Developers assume no liability and are 
not responsible for any misuse and damage caused by using this program.


This project is made as a hobby and passion towards cyber security.

If you notice any issues with the software, please open up an issue. I will gladly take a look at it and try to resolve it. Note that I am by no means, an expert on programming and managing github repository. With that in mind, criticism and advice are very welcome. I am trying to make this program better each day!

In future I will work on: 
1) Option to test parameters from POST requests (maybe load POST request from a file?)
2) Option to test multiple urls and parameters from .txt file
3) Truncation reverse shell exploits - /proc/self/environ, /proc/self/fd, log poisoning
4) SSL support
5) Option to output stdout to multiple formats
6) Create encrypted reverse shell/encoding to avoid detection
7) Option for custom reverse shell if RCE is found, with options to download and upload files easily
