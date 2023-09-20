import threading
import socket
from src.utils import colors
from src.utils.arguments import args

class ICMPThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.result = None

    def run(self):
        try:
            s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
            s.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
            self.result = False

            while True:
                data, addr = s.recvfrom(1024)
                if(data):
                    self.result = True
        except PermissionError:
            if(args.verbose):
                print(colors.red("[-]") + " Raw socket access is not allowed. For blind ICMP command injection test, rerun lfimap as admin/sudo with '-c'")

    def getResult(self):
        return self.result

    def setResult(self, boolean):
        self.result = boolean
