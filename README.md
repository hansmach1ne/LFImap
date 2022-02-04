# lfimap
## Local file inclusion discovery and exploitation tool


### Install
```
git clone https://github.com/hansmach1ne/lfimap.git
cd lfimap/
pip3 install -r requirements.txt
python3 lfimap.py -h

```
### Usage

```

usage: lfimap.py [-D <request>] [-H <header>] [-C <cookie>] [-P <proxy>] [--useragent <agent>] 
[--referer <referer>] [--param <name>] [--no-stop] [-f] [-i] [-d] [-e] [-t][-r] [-c] [--file] [--xss] 
[-a] [-x] [--lhost <lhost>] [--lport <lport>] [-wT <path>] [-wX <path>] [-wC <path>] [-v] [-h] URL

lfimap, Local File Inclusion discovery and exploitation tool

MANDATORY:
  URL                            Specify url, Ex: "http://example.org/vuln.php?param=PWN" 

GENERAL OPTIONS:
  -D <request>                   Do HTTP POST value test. Ex: 'param=PWN'
  -H <header>                    Specify additional HTTP header(s). Ex: 'X-Forwarded-For:127.0.0.1'
  -C <cookie>                    Specify session cookie, Ex: "PHPSESSID=1943785348b45"
  -P <proxy>                     Specify Proxy IP address. Ex: '127.0.0.1:8080'
  --useragent <agent>            Specify HTTP user agent
  --referer <referer>            Specify HTTP referer
  --param <name>                 Specify different test parameter value
  --no-stop                      Don't stop using same method upon findings

ATTACK TECHNIQUE:
  -f, --filter                   Attack using filter:// wrapper
  -i, --input                    Attack using input:// wrapper
  -d, --data                     Attack using data:// wrapper
  -e, --expect                   Attack using expect:// wrapper
  -t, --trunc                    Attack using path truncation with wordlist (default 'short.txt')
  -r, --rfi                      Attack using remote file inclusion
  -c, --cmd                      Attack using command injection
  --file                         Attack using file:// wrapper
  --xss                          Cross site scripting test
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

### Examples 

#### 1) All attacks with '-a' (filter, input, data, expect and file wrappers, remote file inclusion, command injection, XSS, error disclosure).
![all_attacks](https://user-images.githubusercontent.com/57464251/152049407-7c8d5293-a8e6-4c0d-ad08-ae5b95da78a2.PNG)

#### 2) php://input remote command execution attack with '-i' and '-x'.
![rev_shell](https://user-images.githubusercontent.com/57464251/152051221-0f1eab38-69d6-470b-98e2-8345557ebd82.PNG)

#### 3) Post argument testing with '-D'
![postreq_test](https://user-images.githubusercontent.com/57464251/152058166-d33b85dd-426c-4a93-9a32-a8367c372d6c.PNG)


If you notice any issues with the software, please open up an issue. I will gladly take a look at it and try to resolve it. <br>
Pull requests are welcome.

[!] Disclaimer: Lfimap usage for attacking web applications without consent of the application owner is illegal. Developers assume no liability and are 
not responsible for any misuse and damage caused by using this program.
