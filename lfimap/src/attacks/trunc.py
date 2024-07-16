"""Trunc"""
from src.utils.arguments import init_args
from src.httpreqs.request import prepareRequest
from src.httpreqs.request import REQUEST
from src.configs.config import proxies
from src.utils.colors import Colors


def test_trunc(url, post):
    """Test Trunc"""
    args  = init_args()
    if args['verbose']:
        print(
            Colors().blue("[i]")
            + " Testing path truncation using '"
            + args['truncWordlist']
            + "' wordlist...", flush = True
        )

    i = 0

    with open(args['truncWordlist'], "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            u, reqHeaders, postTest = prepareRequest(args['param'], line, url, post)
            # Because of some unicode tests that we do, (wide N for nodejs apps..)
            if postTest:
                postTest = postTest.encode("utf-8")

            _, br = REQUEST(u, reqHeaders, postTest, proxies, "LFI", "TRUNC")

            if not br:
                return

            if i == 1 and args['quick']:
                return

            i += 1

    return
