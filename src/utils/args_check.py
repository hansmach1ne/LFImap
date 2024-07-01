"""Args Check"""
import re
import os
import sys
from datetime import datetime

import requests
from src.httpreqs.httpHeaders import initHttpHeaders
from src.httpreqs.httpHeaders import addHeader
from src.configs import config
from src.utils.arguments import init_args
from src.utils.colors import Colors
from src.utils.parseurl import parseGet
from src.utils.parseurl import parseFormDataLine
from src.utils.parseurl import parse_url_from_request_file
from src.utils.parseurl import parse_http_request_file
from src.utils.parseurl import is_valid_url
from src.utils.parseurl import get_all_params
from src.utils.parseurl import parse_url_parameters
from src.utils.parseurl import is_file_ending_with_newline
from src.utils.parseurl import is_string_in_dict

args  = init_args()

scriptDirectory = os.path.dirname(
    __file__ + os.sep + ".." + os.sep + ".." + os.sep + ".." + os.sep
)
args['scriptDirectory'] = os.path.abspath(scriptDirectory)

args['mode'] = ""
headers = {}


def prepareHeaders():
    """Init User-Agent, Connection, Accept headers + the ones explicitly specified"""
    headersTemp = initHttpHeaders()

    if args['cookie'] is not None:
        headersTemp = addHeader(headersTemp, "Cookie", args['cookie'])
    if args['mode'] == "post":
        headersTemp = addHeader(
            headersTemp, "Content-Type", "application/x-www-form-urlencoded"
        )
    if args['httpheaders']:
        for _, httpheader in enumerate(args['httpheaders']):
            if ":" not in httpheader:
                print(
                    Colors().red("[-] '")
                    + httpheader
                    + "'"
                    + " has no ':' to distinguish parameter name from value. Exiting...",
                    flush = True
                )
                sys.exit(-1)
            elif httpheader[0] == ":":
                print(
                    Colors().red("[-]")
                    + " Header name cannot start with ':' character. Exiting...",
                    flush = True
                )
                sys.exit(-1)
            else:
                headersTemp = addHeader(
                    headersTemp,
                    httpheader.split(":", 1)[0].strip(),
                    httpheader.split(":", 1)[1].lstrip(),
                )

    return headersTemp


def checkArgs():
    """Check Args"""
    args  = init_args()

    urlfile = args['f']
    agent = args['agent']
    referer = args['referer']

    if args['scriptDirectory'] == "":
        separator = ""
    else:
        separator = os.sep

    # Check if mandatory args are provided
    if not args['f'] and not args['url'] and not args['reqfile']:
        print(
            Colors().red("[-]")
            + " Mandatory arguments ('-U', '-F' or '-R') unspecified. Refer to help menu with '-h' or '--help'.",
            flush = True
        )
        sys.exit(-1)

    if not args['param']:
        args['param'] = "PWN"

    # -R specified
    if args['reqfile']:
        if not os.path.exists(args['reqfile']):
            print(
                Colors().red("[-]")
                + " Specified request file '"
                + args['reqfile']
                + "' doesn't exist. Exiting...",
                flush = True
            )
            sys.exit(-1)

        # RFC states that new line should be at the end, some servers might not even accept the request without it.
        if not is_file_ending_with_newline(args['reqfile']):
            print(
                Colors().red("[-]")
                + " Request file '"
                + args['reqfile']
                + "' doesn't contain empty space after the headers. Please add it and try again...",
                flush = True
            )
            sys.exit(-1)
        elif os.path.exists(args['reqfile']):
            args['url'] = parse_url_from_request_file(args['reqfile'], args['force_ssl'])
            config.url = args['url']
            args['method'], args['httpheaders'], args['postreq'] = parse_http_request_file(
                args['reqfile']
            )
        else:
            print(
                Colors().red("[-]")
                + " Specified request file '"
                + args['reqfile']
                + "' doesn't exist. Exiting...",
                flush = True
            )
            sys.exit(-1)

    # args['mode'] is needed for exploitation modules to better understand in what context the vulnerability lies

    # if '-F' is provided, set mode to file
    if args['f']:
        args['mode'] = "file"
    # if '-D' is provided, set mode to post
    elif args['postreq']:
        args['mode'] = "post"
    # otherwise, set mode to get
    else:
        args['mode'] = "get"

    tempUrl = args['url']
    # IF URL protocol not specified, add it
    if args['mode'] != "file":
        if not tempUrl.startswith("http") and not tempUrl.startswith("socks"):
            if args['force_ssl']:
                if args['verbose']:
                    print(
                        Colors().blue("[i]")
                        + " No URL scheme provided. Defaulting to https.",
                        flush = True
                    )
                args['url'] = "https://" + tempUrl
                tempUrl = "https://" + tempUrl
                config.url = "https://" + tempUrl

            else:
                if args['verbose']:
                    print(
                        Colors().blue("[i]")
                        + " No URL scheme provided. Defaulting to http.",
                        flush = True
                    )
                args['url'] = "http://" + tempUrl
                tempUrl = "http://" + tempUrl
                config.url = "http://" + tempUrl

        # Check if URL is valid
        if not is_valid_url(tempUrl):
            print(tempUrl + " is not valid URL."),
            flush = True
            sys.exit(-1)
    # file mode
    else:
        # Check if file exists
        if not os.path.exists(args['f']):
            print(
                Colors().red("[-]") + " File '" + args['f'] + "' doesn't exist. Exiting...",
                flush = True
            )
            sys.exit(-1)
        else:
            # Check if every line has defined protocol, if not modify the file and prepend it
            # Also check if every line has at least one parameter to test
            with open(args['f'], "r", encoding="latin1") as rf:
                lines = rf.readlines()
            for index, line in enumerate(lines):
                line = line.strip()
                protocol = "https://" if args['force_ssl'] else "http://"

                # Ignore empty lines from urlfile
                if line == "":
                    continue

                # If first key of the dictionary is empty, there are no parameters to test, skip
                first_key = next(iter(get_all_params(line)), None)
                if first_key == "":
                    if args['verbose']:
                        print(
                            Colors().blue("[i]")
                            + " URL line #"
                            + str(index + 1)
                            + ". "
                            + "'"
                            + line
                            + "' contains no parameters to test. Ignoring this entry...",
                            flush = True
                        )
                    continue
                elif line.startswith("http"):
                    config.urls.append(line)
                else:
                    config.urls.append(protocol + line)

    # -F specified, parse URL one by one
    if args['f']:
        parsedList = []
        for l in config.urls:
            l = l.strip()
            if args['param'] not in l:
                if (
                    parse_url_parameters(l) not in parsedList
                    and parseGet(l) not in config.parsedUrls
                ):
                    config.parsedUrls.append(parseGet(l))
                args['automaticGetParams'] = True
            else:
                args['automaticGetParams'] = False
                if (
                    parse_url_parameters(l) not in parsedList
                    and l.strip() not in config.parsedUrls
                ):
                    config.parsedUrls.append(l)

        # Convert each parsed URL to a single list of URLs
        result_list = []
        for sublist in config.parsedUrls:
            if isinstance(sublist, list):
                result_list.extend(sublist)
            else:
                result_list.append(sublist)
        config.parsedUrls = result_list.copy()

    # -F is not specified, parse single URL
    else:
        if args['param'] not in args['url']:
            config.url = args['url']
            args['url'] = parseGet(args['url'])
            args['automaticGetParams'] = True
        else:
            args['automaticGetParams'] = False
            config.url = args['url']
            args['url'] = [args['url']]

    # Parse -D or -J FORM-data
    if not args['reqfile']:
        if args['f']:
            args['postreq'] = False
        elif args['postreq']:
            config.postreq = args['postreq']
            args['postreq'] = parseFormDataLine(args['postreq'])
        # elif(args['json']):
        #    config.jsonreq = args['json']
        #    args['postreq'] = parseFormDataLine(args['json'])
        #    print(args['postreq'])
        else:
            args['postreq'] = False

    if not args['f']:
        if (
            tempUrl == "".join(args['url'])
            and not args['postreq']
            and args['param'] not in tempUrl
        ):
            if args['reqfile'] and not is_string_in_dict(args['param'], args['httpheaders']):
                print(Colors().red("[-]") + " No parameters to test. Exiting...", flush = True)
                sys.exit(-1)

    # If -M is not specified, set the method to test manually
    if not args['method'] and not args['reqfile']:
        if args['f']:
            args['method'] = "GET"
        elif args['postreq']:
            args['method'] = "POST"
        elif args['url']:
            args['method'] = "GET"

    if not args['postreq']:
        config.postreq = None

    # Check if provided trunc wordlist exists
    if args['truncWordlist']:
        if not os.path.isfile(args['truncWordlist']):
            print(
                Colors().red("[-]")
                + " Specified truncation wordlist '"
                + args['truncWordlist']
                + "' doesn't exist. Exiting...",
                flush = True
            )
            sys.exit(-1)
    else:
        if args['uselong']:
            args['truncWordlist'] = (
                args['scriptDirectory']
                + separator
                + "src"
                + separator
                + "wordlists"
                + separator
                + "long.txt"
            )
        else:
            args['truncWordlist'] = (
                args['scriptDirectory']
                + separator
                + "src"
                + separator
                + "wordlists"
                + separator
                + "short.txt"
            )
        if (not os.path.exists(args['truncWordlist'])) and (args['test_all'] or args['trunc']):
            print(
                Colors().red("[-]")
                + " Cannot locate "
                + args['truncWordlist']
                + " wordlist. Since '-a' or '-t' was specified, lfimap will exit...",
                flush = True
            )
            sys.exit(-1)

    # Check if log file is correct and writeable
    if args['log']:
        try:
            if os.path.exists(args['log']):
                print(
                    Colors().blue("[i]")
                    + " Log destination file '"
                    + args['log']
                    + "' already exists",
                    flush = True
                )
                users_input = input(
                    "[?] Do you want to continue and append logs to it? Y/n: "
                )
                if users_input == "n" and users_input != "N":
                    print("User exit...", flush = True)
                    sys.exit(-1)
                else:
                    print("", flush = True)
            else:
                if not os.path.isabs(args['log']):
                    script_dir = os.path.dirname(__file__)
                    rel_path = args['log']
                    abs_file_path = os.path.join(script_dir, rel_path)
                else:
                    abs_file_path = args['log']
                if not os.path.isdir(os.path.dirname(os.path.abspath(abs_file_path))):
                    os.mkdir(os.path.dirname(os.path.abspath(abs_file_path)))
                else:
                    with open(abs_file_path, "a", encoding="latin1") as fp:
                        fp.write("-----------START-----------\n")
                        fp.write(
                            "# Starting log: "
                            + str(datetime.now().strftime("%d/%m/%Y %H:%M:%S"))
                            + "\n"
                        )
                        fp.write("# Arguments: " + " ".join(sys.argv) + "\n")
                        fp.write("---------------------------")
                        fp.write("\n\n")
        except:
            print(
                Colors().red("[-]")
                + " Failed creating log file: "
                + args['log']
                + ". Check if you specified correct path and have correct permissions...",
                flush = True
            )
            sys.exit(-1)

    # Checks if '--lhost' and '--lport' are provided with '-x'
    if args['revshell']:
        if not args['lhost']:
            print(
                Colors().red("[-]")
                + " Please, specify localhost IP ('--lhost') for reverse shell. Exiting...",
                flush = True
            )
            sys.exit(-1)

        if not args['lport']:
            print(
                Colors().red("[-]")
                + " Please, specify localhost PORT number ('--lport') for reverse shell. Exiting...",
                flush = True
            )
            sys.exit(-1)

        else:
            reg = r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
            if not re.match(reg, args['lhost']):
                print(Colors().red("[-]") + " LHOST IP address is not valid. Exiting...", flush = True)
                sys.exit(-1)

            if args['lport'] < 1 or args['lport'] > 65534:
                print(
                    Colors().red("[-]")
                    + " LPORT must be between 1 and 65534. Exiting ...",
                    flush = True
                )
                sys.exit(-1)

    # Check if CSRF URL is correctly specified
    if args['csrfUrl']:
        if not args['csrfUrl'].startswith("http"):
            if args['verbose']:
                print(
                    Colors().blue("[i]")
                    + " No URL scheme provided in csrf extraction endpoint. Defaulting to http...",
                    flush = True
                )
            args['csrfUrl'] = "http://" + args['csrfUrl']

    if args['csrfUrl'] and not is_valid_url(args['csrfUrl']):
        print(
            Colors().red("[-]")
            + " Specified csrf extraction URL '"
            + args['csrfUrl']
            + "' is not valid. Exiting...",
            flush = True
        )
        sys.exit(-1)

    # Check if second order URL is correctly specified
    if args['checkUrl']:
        if not args['checkUrl'].startswith("http"):
            if args['verbose']:
                print(
                    Colors().blue("[i]")
                    + " No URL scheme provided in second order check endpoint. Defaulting to http...",
                    flush = True
                )
            args['checkUrl'] = "http://" + args['checkUrl']
        print(
            Colors().blue("[i]")
            + " Second order endpoint is specified. After each payload, lookup is done to check if payload triggered interesting behaviour.",
            flush = True
        )

    if args['checkUrl'] and not is_valid_url(args['checkUrl']):
        print(
            Colors().red("[-]")
            + " Specified second order check URL '"
            + args['checkUrl']
            + "' is not valid. Exiting...",
            flush = True
        )
        sys.exit(-1)

    # Check if proxy is correct
    if args['proxyAddr']:
        try:
            if "http" not in args['proxyAddr'] and "socks" not in args['proxyAddr']:
                if args['verbose']:
                    print(
                        Colors().blue("[i]")
                        + " No proxy scheme provided. Defaulting to http...",
                        flush = True
                    )
                args['proxyAddr'] = "http://" + args['proxyAddr']

            r = requests.get(args['proxyAddr'], timeout=5, verify=False)
            if r.status_code >= 500:
                print(
                    Colors().red("[-]")
                    + " Proxy is available, but it returns server-side error code >=500. Exiting...",
                    flush = True
                )
                sys.exit(-1)
        except:
            print(Colors().red("[-]") + " Proxy is not available. Exiting...", flush = True)
            sys.exit(-1)
    else:
        config.tOut = 1

    # Setup a temporary argument placeholder.
    exists = False
    TEMP = ["CMD", "TEMP", "LFIMAP", "LFI"]

    # TODO check this
    if args['mode'] != "file":
        for item in TEMP:
            if item not in args['url']:
                config.tempArg = item
                break
    else:
        with open(args['f'], "r", encoding="latin1") as fi:
            lines = fi.read().splitlines()
            for item in TEMP:
                for line in lines:
                    if item in line:
                        exists = True
                if not exists:
                    config.tempArg = item
                    break

    if args['encodings']:
        for e in args['encodings']:
            if e != "U" and e != "B":
                print(
                    "[!] Invalid payload encoding specified. Please use 'U' for URL or 'B' for BASE64 encoded payload.",
                    flush = True
                )
                sys.exit(-1)

    if args['mode'] == "file" and args['revshell']:
        print(
            "[!] Specifying multiple url testing with '-F' and reverse shell attack with '-x' is NOT RECOMMENDED, unless you know what you're doing.",
            flush = True
        )
        option = input("[?] Are you sure you want to continue? y/n: ")
        if option != "y" and option != "Y":
            print(Colors().blue("[i]") + " User selected exit option. Exiting...", flush = True)
            sys.exit(-1)

    if args['quick'] and args['verbose']:
        print(
            Colors().blue("[i]") + " Quick mode enabled, LFImap will use fewer payloads.",
            flush = True
        )

    if not args['reqfile']:
        # Preparing headers
        headers = prepareHeaders()
        if args['cookie'] is not None:
            headers = addHeader(headers, "Cookie", args['cookie'])
        if args['mode'] == "post":
            # if(args['json']): headers = addHeader(headers, "Content-Type", "application/json")
            # else:
            headers = addHeader(
                headers, "Content-Type", "application/x-www-form-urlencoded"
            )
        if args['httpheaders']:
            for _, httpheader in enumerate(args['httpheaders']):
                if ":" not in httpheader:
                    print(
                        Colors().red("[-] '")
                        + httpheader
                        + "'"
                        + " has no ':' to distinguish parameter name from value. Exiting...",
                        flush = True
                    )
                    sys.exit(-1)
                elif httpheader[0] == ":":
                    print(
                        Colors().red("[-]")
                        + " Header name cannot start with ':' character. Exiting...",
                        flush = True
                    )
                    sys.exit(-1)
                else:
                    headers = addHeader(
                        headers,
                        httpheader.split(":", 1)[0].strip(),
                        httpheader.split(":", 1)[1].lstrip(),
                    )

        args['httpheaders'] = headers

    # warning if cookie/Authorization header is not provided
    cookieIsPresent = False
    for key, value in args['httpheaders'].items():
        if key.lower() == "cookie" or key.lower() == "authorization":
            cookieIsPresent = True
            break
    if not cookieIsPresent:
        if args['verbose']:
            print(
                Colors().blue("[i]")
                + " Session information is not provided. LFImap might have troubles finding vulnerabilities if testing endpoint requires authentication.",
                flush = True
            )

    return True
