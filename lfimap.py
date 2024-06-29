#!/usr/bin/env python3

import sys

from urllib3.exceptions import NewConnectionError
from requests.exceptions import ConnectTimeout
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Disable/Mute TLS errors
from requests.packages.urllib3 import disable_warnings

# Import configurations
from src.configs import config

# Import utilities
from src.utils.arguments import ArgumentHandler
from src.utils.args_check import checkArgs
from src.utils.cleanup import lfimap_cleanup
from src.utils.stats import stats

# Import custom request functionality
from src.httpreqs.request import prepareRequest
from src.httpreqs.request import REQUEST

disable_warnings(InsecureRequestWarning)

# Import attack modules
from src.attacks.heur import test_heuristics
from src.attacks.filter import test_filter
from src.attacks.input import test_input
from src.attacks.data import test_data
from src.attacks.expect import test_expect
from src.attacks.rfi import test_rfi
from src.attacks.cmdi import test_cmd_injection
from src.attacks.file import test_file_trunc
from src.attacks.trunc import test_trunc
from src.utils import colors
from src.utils.parseurl import get_params_with_param
from src.utils.parseurl import post_params_with_param
from src.utils.parseurl import getHeadersToTest
from src.utils.parseurl import is_valid_url
from src.httpreqs.request import extract_all_parameters
from src.httpreqs.request import extract_input_fields


def main():
    args = ArgumentHandler()

    config.proxies["http"] = args.args['proxyAddr']
    config.proxies["https"] = args.args['proxyAddr']

    config.lastPrintedStringLen = 1
    # If multiple URLS are specified from a file
    if args.args['f']:

        for iteration, url in enumerate(config.parsedUrls):
            if not args.args['postreq'] or "".join(args.args['postreq'][0]) == "":
                args.args['postreq'] = [""]

                # Just in case check if URL is correctly formatted, it should be always correct up to this point, though...
                if not is_valid_url(url):
                    print(
                        colors.red("\n[-]")
                        + " URL '"
                        + url
                        + "'' is not valid. Skipping..."
                    )
                    continue

                print(
                    "\n"
                    + colors.lightblue("[i]")
                    + " Parsing URL ["
                    + str(iteration + 1)
                    + "/"
                    + str(len(config.parsedUrls))
                    + "]: '"
                    + url
                    + "'"
                )

            # CSRF token refresh with -F is not supported yet #TODO
            args.args['updateCsrfToken'] = False
            args.args['previouscsrf'] = False

            # POST testing with -F is not supported
            args.args['is_tested_param_post'] = False

            try:
                # Check if url is accessible
                tempUrl, headers, postTest = prepareRequest(args.args['param'], "test", url, "")
                try:
                    r, _ = REQUEST(
                        tempUrl, headers, postTest, config.proxies, "test", "test"
                    )
                    okCode = False

                    # In case expection has occurred and not caught
                    if r == False:
                        continue

                    if args.args['http_valid']:
                        for http_code in args.args['http_valid']:
                            if http_code == r.status_code:
                                okCode = True

                        if not okCode:
                            print(
                                colors.red("[-] ")
                                + " URL '"
                                + tempUrl
                                + "' is not accessible. HTTP code "
                                + str(r.status_code)
                                + "."
                            )
                            print(
                                colors.blue("[i]")
                                + " Try specifying parameter --http-ok "
                                + str(r.status_code)
                                + "\n"
                            )
                            continue
                    else:
                        if r.status_code != 200 and r.status_code != 204:
                            print(
                                colors.red("[-]")
                                + " URL '"
                                + tempUrl
                                + "' is not accessible. HTTP code "
                                + str(r.status_code)
                                + ". Skipping..."
                            )
                            print(
                                colors.blue("[i]")
                                + " Try specifying parameter --http-ok "
                                + str(r.status_code)
                                + "\n"
                            )
                            continue
                except:
                    print(
                        colors.red("[-]")
                        + " Exception occurred while accessing '"
                        + tempUrl
                        + "'. Skipping..."
                    )
                    raise

                relativeVulnCount = stats["vulns"]
                stats["urls"] += 1

                if not args.args['postreq'] or "".join(args.args['postreq'][0]) == "":
                    if not args.args['verbose']:
                        print("")
                    print(
                        colors.yellow("[i]")
                        + " Testing GET '"
                        + get_params_with_param(url)
                        + "' parameter..."
                    )

                # Perform all tests
                if args.args['test_all']:
                    test_heuristics(url, "")
                    test_filter(url, "")
                    test_input(url, "")
                    test_data(url, "")
                    test_expect(url, "")
                    test_rfi(url, "")
                    test_file_trunc(url, "")
                    test_trunc(url, "")
                    test_cmd_injection(url, "")

                    if stats["vulns"] == relativeVulnCount:
                        print(
                            colors.red("[-]")
                            + " GET parameter '"
                            + get_params_with_param(url)
                            + "' doesn't seem to be vulnerable.\n"
                        )
                    continue

                default = True

                if args.args['heuristics']:
                    default = False
                    test_heuristics(url, "")
                if args.args['php_filter']:
                    default = False
                    test_filter(url, "")
                if args.args['php_input']:
                    default = False
                    test_input(url, "")
                if args.args['php_data']:
                    default = False
                    test_data(url, "")
                if args.args['php_expect']:
                    default = False
                    test_expect(url, "")
                if args.args['rfi']:
                    default = False
                    test_rfi(url, "")
                if args.args['file']:
                    default = False
                    test_file_trunc(url, "")
                if args.args['trunc']:
                    default = False
                    test_trunc(url, "")
                if args.args['cmd']:
                    default = False
                    test_cmd_injection(url, "")

                # Default behaviour
                if default:
                    test_filter(url, "")
                    test_input(url, "")
                    test_data(url, "")
                    test_expect(url, "")
                    test_rfi(url, "")
                    test_file_trunc(url, "")
                    test_trunc(url, "")

                if stats["vulns"] == relativeVulnCount:
                    print(
                        colors.red("[-]")
                        + " GET parameter '"
                        + get_params_with_param(url)
                        + "' doesn't seem to be vulnerable.\n"
                    )

            except ConnectTimeout:
                print(colors.red("[-]") + " URL '" + url + "' timed out. Skipping...")
            except ConnectionRefusedError:
                print(colors.red("[-]") + " Failed to establish connection to " + url)
            except NewConnectionError:
                print(colors.red("[-]") + " Failed to establish connection to " + url)
            except OSError:
                print(colors.red("[-]") + " Failed to establish connection to " + url)
            except KeyboardInterrupt:
                print("\nKeyboard interrupt detected. Exiting...")
                lfimap_cleanup(config.webDir, stats)
            except:
                raise

        lfimap_cleanup(config.webDir, stats)

    # If single URL is specified
    else:
        turls = []  # list of strings
        tposts = []  # list of strings
        theaders = []  # list of dicts

        # Find out where the args.args['param'] are located at
        if args.args['param'] in config.url:
            pwnInGetExists = True
        else:
            pwnInGetExists = False

        if config.postreq and args.args['param'] in config.postreq:
            pwnInPostExists = True
        else:
            pwnInPostExists = False

        found_in_headkeys = args.args['param'] in args.args['httpheaders'].keys()
        found_in_headvalues = args.args['param'] in (
            str(value) for value in args.args['httpheaders'].values()
        )

        if found_in_headkeys or found_in_headvalues:
            pwnInHeadersExists = True
        else:
            pwnInHeadersExists = False

        # Default val
        args.args['updateCsrfToken'] = False
        args.args['previouscsrf'] = False

        tempUrl = ""

        # Test header
        if pwnInHeadersExists:
            tempUrl, headers, postTest = prepareRequest(
                args.args['param'], args.args['param'], config.url, config.postreq
            )
            turls.append(tempUrl)
            theaders.append(headers)
            tposts.append(postTest)
        else:
            if pwnInGetExists or not pwnInPostExists and args.args['param'] in args.args['url'][0]:
                # If the PWN is not in the url, parse all of the parameters
                if args.args['param'] not in config.url:
                    for iteration, url in enumerate(args.args['url']):
                        tempUrl, headers, postTest = prepareRequest(
                            args.args['param'], args.args['param'], url, config.postreq
                        )
                        turls.append(tempUrl)
                        theaders.append(headers)
                        tposts.append(postTest)

                # Parse only parameters that have PWN keyword
                else:
                    pwnInGetExists = True
                    tempUrl, headers, postTest = prepareRequest(
                        args.args['param'], args.args['param'], config.url, config.postreq
                    )
                    turls.append(tempUrl)
                    theaders.append(headers)
                    tposts.append(postTest)

            if not pwnInGetExists and not pwnInHeadersExists:
                # If the PWN keyword is in the FORM-data line
                if config.postreq and args.args['param'] not in config.postreq:
                    for i, post in enumerate(args.args['postreq']):
                        tempUrl, headers, postTest = prepareRequest(
                            args.args['param'], args.args['param'], config.url, post
                        )
                        turls.append(tempUrl)
                        theaders.append(headers)
                        tposts.append(postTest)
                elif config.postreq != None:
                    tempUrl, headers, postTest = prepareRequest(
                        args.args['param'], args.args['param'], config.url, config.postreq
                    )
                    turls.append(tempUrl)
                    theaders.append(headers)
                    tposts.append(postTest)

        # No arguments found to test, if this is not set.
        if tempUrl == None or tempUrl == "":
            print(colors.red("[-]") + " No arguments to test. Exiting...")
            sys.exit(-1)

        # Test request to see if the site is accessible
        # r,_ = REQUEST(tempUrl, headers, postTest, config.proxies, "test", "test")

        # print(config.url)
        # print(tempUrl)

        # print(postTest)
        # print(config.postreq)

        # Check if csrf token is being used.
        # print(args.args['csrfData'])
        # print(config.postreq)

        # TODO edge case where the url is not specified, but the csrf token is inside the request.?
        csrf_r = ""
        if args.args['csrfUrl']:
            # Send request to the csrf token endpoint
            if not args.args['csrfMethod']:
                args.args['csrfMethod'] = "GET"
            if not args.args['csrfData']:
                if args.args['postreq']:
                    args.args['csrfData'] = args.args['postreq'][0]
                else:
                    args.args['csrfData'] = ""
            csrf_r, _ = REQUEST(
                args.args['csrfUrl'],
                headers,
                args.args['csrfData'],
                config.proxies,
                "test",
                "test",
                exploit=False,
                followRedirect=True,
                isCsrfRequest=True,
            )

        r, _ = REQUEST(
            config.url,
            headers,
            config.postreq,
            config.proxies,
            "test",
            "test",
            exploit=False,
            followRedirect=True,
            isCsrfRequest=False,
        )
        if not args.args['http_valid']:
            args.args['http_valid'] = [200, 204, 301, 302, 303]

        if (isinstance(r, bool) and not r) or (isinstance(r, str) and not r.text):
            print(
                colors.red("[-]")
                + " Something unexpected has happened, initial testing response is not clearly received. Please check your switches and url endpoint(s). Exiting..."
            )
            sys.exit(-1)

        if r and r.status_code >= 500:
            if r.status_code not in args.args['http_valid']:
                print(
                    colors.red("[-]")
                    + " Initial request yielded "
                    + str(r.status_code)
                    + " response. Application might not be available. To force-continue specify '--http-ok "
                    + str(r.status_code)
                    + "' to treat it as valid."
                )
                sys.exit(-1)

        if (
            "no&#32;response&#32;received&#32;from&#32;remote&#32;server&#46;"
            in r.text.lower()
        ):
            print(
                colors.red("[-]")
                + " No response received from remote server. This could be proxy's response due to unresponsive application server."
            )
            inp = input(
                "\n"
                + colors.yellow("[?]")
                + " Web application might not be available. Do you still want to force-continue [y/N] "
            )
            if inp in ["n", "N", ""]:
                print("User interrupt, exiting...")
                sys.exit(-1)

        if not r and not args.args['no_stop']:
            lfimap_cleanup(config.webDir, stats)

        if csrf_r:
            input_fields = extract_input_fields(csrf_r.text)
            # Post request[0] is enough, because it's a list of permutations anyways, we need parameter names

            parameters = extract_all_parameters(config.url, config.postreq)
        else:
            input_fields = extract_input_fields(r.text)
            parameters = extract_all_parameters(config.url, config.postreq)

        inp = "Initial"
        # Check if csrf token is present in the request.
        if args.args['csrfParameter']:
            if args.args['csrfParameter'] not in parameters.keys():
                print(
                    colors.red("[-]")
                    + " Specified csrf parameter '"
                    + args.args['csrfParameter']
                    + "' not found in the initial request. LFImap will not be able to refresh the csrf token."
                )
                args.args['updateCsrfToken'] = False
            elif args.args['csrfParameter'] not in input_fields.keys():
                print(
                    colors.red("[-]")
                    + " Specified csrf parameter '"
                    + args.args['csrfParameter']
                    + "' not found in the initial response. LFImap will not be able to refresh the csrf token."
                )
                args.args['updateCsrfToken'] = False
            elif parameters[args.args['csrfParameter']] != input_fields[args.args['csrfParameter']]:
                inp = input(
                    "\n"
                    + colors.yellow("[?]")
                    + " It appears that CSRF value is refreshed after each request. Do you wish to automatically update tokens? [Y/n] "
                )
            else:
                print(
                    colors.blue("[i]")
                    + " It appears that CSRF token is not refreshed after each request. LFImap will not automatically update the csrf token in requests"
                )
        else:
            for param_name in parameters.keys():
                if param_name in config.csrf_params:
                    args.args['csrfParameter'] = param_name
                    # If there is the same key value pair in both dicts
                    if any(item in input_fields.items() for item in parameters.items()):
                        print(
                            colors.blue("[i]")
                            + " Parameter '"
                            + param_name
                            + "' appears to be anti-forgery token, but it hasn't been refreshed by the web application. LFImap will not auto-refresh csrf token value"
                        )
                        args.args['updateCsrfToken'] = False
                    elif len(input_fields) == 0:
                        if not args.args['csrfUrl']:
                            print(
                                colors.blue("[i]")
                                + " Parameter '"
                                + param_name
                                + "' appears to be anti-forgery token, however the csrf token is not present in the response. Please specify the  '--csrf-url' to auto-refresh the token."
                            )
                            args.args['updateCsrfToken'] = False
                    elif (
                        parameters[args.args['csrfParameter']]
                        != input_fields[args.args['csrfParameter']]
                    ):
                        inp = input(
                            "\n"
                            + colors.yellow("[?]")
                            + " It appears that CSRF value is refreshed after each request. Do you wish to automatically update tokens? [Y/n] "
                        )
                    else:
                        print(
                            colors.blue("[i]")
                            + " It appears that CSRF token is not refreshed after each request. LFImap will not automatically update the csrf token in requests"
                        )

        if inp in ["y", "Y", ""]:
            args.args['updateCsrfToken'] = True
        else:
            args.args['updateCsrfToken'] = False

        okCode = False
        if args.args['http_valid']:
            for http_code in args.args['http_valid']:
                if http_code == r.status_code:
                    okCode = True

            if r and not okCode:
                print(
                    colors.red("[-] ")
                    + tempUrl
                    + " is not accessible. HTTP code "
                    + str(r.status_code)
                    + "."
                )
                print(
                    colors.blue("[i]")
                    + " Try specifying parameter --http-ok "
                    + str(r.status_code)
                    + "\n"
                )
                if not args.args['no_stop']:
                    sys.exit(-1)

        else:
            if r and r.status_code != 200 and r.status_code != 204:
                print(
                    colors.red("[-]")
                    + tempUrl
                    + " is not accessible. HTTP code "
                    + str(r.status_code)
                    + ".  Exiting..."
                )
                print(
                    colors.blue("[i]")
                    + " Try specifying parameter --http-ok "
                    + str(r.status_code)
                    + "\n"
                )
                if not args.args['no_stop']:
                    sys.exit(-1)

        # Main loop that will perform testing
        for iteration, url in enumerate(turls):
            post = tposts[iteration]
            headers = theaders[iteration]

            if pwnInHeadersExists:
                # Handle plural
                if "," in getHeadersToTest(headers):
                    print(
                        "\n"
                        + colors.yellow("[i]")
                        + " Testing headers '"
                        + getHeadersToTest(headers)
                        + "'"
                    )
                else:
                    print(
                        "\n"
                        + colors.yellow("[i]")
                        + " Testing header '"
                        + getHeadersToTest(headers)
                        + "'"
                    )

            if args.args['param'] in url:
                print(
                    "\n"
                    + colors.yellow("[i]")
                    + " Testing GET '"
                    + get_params_with_param(url)
                    + "' parameter..."
                )
                args.args['is_tested_param_post'] = False  # Needed to handle -i

            elif args.args['postreq'] and args.args['param'] in post:
                print(
                    "\n"
                    + colors.yellow("[i]")
                    + " Testing form-line '"
                    + post_params_with_param(post)
                    + "' parameter..."
                )
                args.args['is_tested_param_post'] = True  # Needed to handle -i
            else:
                is_tested_param_post = False

            # Skip CSRF parameter testing..
            if args.args['csrfParameter']:
                if (
                    args.args['csrfParameter'] + "=" + args.args['param'] in url
                    or args.args['csrfParameter'] + "=" + args.args['param'] in post
                ):
                    print(
                        colors.blue("[-]") + " Skipping testing of anti-forgery token"
                    )
                    continue
            relativeVulnCount = stats["vulns"]
            stats["urls"] += 1

            # Perform all tests
            if args.args['test_all']:
                test_heuristics(url, post)
                test_filter(url, post)
                test_input(url, post)
                test_data(url, post)
                test_expect(url, post)
                test_file_trunc(url, post)
                test_rfi(url, post)
                test_trunc(url, post)
                test_cmd_injection(url, post)

                if stats["vulns"] == relativeVulnCount and pwnInHeadersExists:
                    # Handle plural
                    if "," in getHeadersToTest(headers):
                        print(
                            colors.red("[-]")
                            + " Headers '"
                            + getHeadersToTest(headers)
                            + "' doesn't seem to be vulnerable."
                        )
                    else:
                        print(
                            colors.red("[-]")
                            + " Header '"
                            + getHeadersToTest(headers)
                            + "' doesn't seem to be vulnerable."
                        )

                if stats["vulns"] == relativeVulnCount:
                    if args.args['param'] in url:
                        print(
                            colors.red("[-]")
                            + " GET parameter '"
                            + get_params_with_param(url)
                            + "' doesn't seem to be vulnerable...."
                        )
                    if args.args['postreq'] and args.args['param'] in post:
                        print(
                            colors.red("[-]")
                            + " Form-line parameter '"
                            + post_params_with_param(post)
                            + "' doesn't seem to be vulnerable...."
                        )
                continue

            default = True

            if args.args['heuristics']:
                default = False
                test_heuristics(url, post)
            if args.args['php_filter']:
                default = False
                test_filter(url, post)
            if args.args['php_input']:
                default = False
                test_input(url, post)
            if args.args['php_data']:
                default = False
                test_data(url, post)
            if args.args['php_expect']:
                default = False
                test_expect(url, post)
            if args.args['file']:
                default = False
                test_file_trunc(url, post)
            if args.args['rfi']:
                default = False
                test_rfi(url, post)
            if args.args['trunc']:
                default = False
                test_trunc(url, post)
            if args.args['cmd']:
                default = False
                test_cmd_injection(url, post)

            # Default behaviour
            if default:
                test_filter(url, post)
                test_input(url, post)
                test_data(url, post)
                test_expect(url, post)
                test_file_trunc(url, post)
                test_rfi(url, post)
                test_trunc(url, post)

            if stats["vulns"] == relativeVulnCount and pwnInHeadersExists:
                # Handle plural
                if "," in getHeadersToTest(headers):
                    print(
                        colors.blue("[i]")
                        + " Headers '"
                        + getHeadersToTest(headers)
                        + "' doesn't seem to be vulnerable."
                    )
                else:
                    print(
                        colors.blue("[i]")
                        + " Header '"
                        + getHeadersToTest(headers)
                        + "' doesn't seem to be vulnerable."
                    )

            if stats["vulns"] == relativeVulnCount:
                if args.args['param'] in url:
                    print(
                        colors.red("[-]")
                        + " GET parameter '"
                        + get_params_with_param(url)
                        + "' doesn't seem to be vulnerable...."
                    )
                if args.args['postreq'] and args.args['param'] in post:
                    print(
                        colors.red("[-]")
                        + " Form-line parameter '"
                        + post_params_with_param(post)
                        + "' doesn't seem to be vulnerable...."
                    )

        lfimap_cleanup(config.webDir, stats)


if __name__ == "__main__":

    # Check command-line arguments
    if not checkArgs():
        sys.exit(-1)

    main()
