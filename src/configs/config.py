checkedHosts = []
exploits = []
proxies = {}
rfi_test_port = 8000
tOut = None
initialReqTime = 0
scriptName = ""
tempArg = ""
webDir = ""
skipsqli = False
previousPrint = ""
urls = []
parsedUrls = []
maxTimeout = None

#Add them from the most complex one to the least complex. This is important.
TO_REPLACE = [
            "Windows/System32/drivers/etc/hosts", "C%3A%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts",
            "file://C:\Windows\System32\drivers\etc\hosts", "%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts",
            "C:\Windows\System32\drivers\etc\hosts", "Windows\\System32\\drivers\\etc\\hosts",
            "%windir%\System32\drivers\etc\hosts",

            "file%3A%2F%2F%2Fetc%2Fpasswd%2500", "file%3A%2F%2F%2Fetc%2Fpasswd",
            "cat%24IFS%2Fetc%2Fpasswd", "cat${IFS%??}/etc/passwd", "/sbin/cat%20/etc/passwd",
            "/sbin/cat /etc/passwd", "cat%20%2Fetc%2Fpasswd", "cat${IFS}/etc/passwd",
            "cat /etc/passwd", "%2Fetc%2Fpasswd", "/etc/passwd",
            "ysvznc", "ipconfig", 'aahgpz"ptz>e<atzf', "aahgpz%22ptz%3Ee%3Catzf", #XSS lookup values need to be last
            ]

KEY_WORDS = ["root:x:0:0", "<IMG sRC=X onerror=jaVaScRipT:alert`xss`>",
            "<img src=x onerror=javascript:alert`xss`>",
            "cm9vdDp4OjA", "Ond3dy1kYX", "ebbg:k:0:0", "d3d3LWRhdG", "aahgpz\"ptz>e<atzf",
            "jjj-qngn:k", "daemon:x:1:", "r o o t : x : 0 : 0", "ZGFlbW9uOng6",
            "; for 16-bit app support", "sample HOSTS file used by Microsoft",
            "iBvIG8gdCA6IHggOiA", "OyBmb3IgMTYtYml0IGFwcCBzdXBw", "c2FtcGxlIEhPU1RTIGZpbGUgIHVzZWQgYnkgTWljcm9zb2", 
            "Windows IP Configuration", "OyBmb3IgMT", "; sbe 16-ovg ncc fhccbeg",
            "; sbe 16-ovg ncc fhccbeg", "fnzcyr UBFGF svyr hfrq ol Zvpebfbsg",
             ";  f o r  1 6 - b i t  a p p", "fnzcyr UBFGF svyr hfrq ol Zvpebfbsg",
            "c2FtcGxlIEhPU1RT", "=1943785348b45", "www-data:x", "PD9w",
            "961bb08a95dbc34397248d92352da799", "PCFET0NUWVBFIGh0b",
            "PCFET0N", "PGh0b"]

