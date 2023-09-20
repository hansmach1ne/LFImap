import base64
import urllib.parse as urlparse

from src.utils.arguments import args

def base64_encode(string):
    return base64.b64encode(bytes(string, 'utf-8')).decode()

def urlencode(string):
    return urlparse.quote(string, safe='')

def encode(payload):
    if(args.encodings):
        for encoding in args.encodings:
            if(encoding == "B"):
                payload = base64_encode(payload)
            elif(encoding == "U"):
                payload = urlencode(payload)
    return payload
