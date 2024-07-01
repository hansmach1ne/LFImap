"""Stats"""
stats = {}

# Function that will calculate statistics and print out the numbers

def init_stats():
    """Initialize the stats values"""

    stats["getRequests"] = 0
    stats["postRequests"] = 0
    stats["requests"] = 0
    stats["info"] = 0
    stats["vulns"] = 0
    stats["urls"] = 0

def print_stats():
    """Print stats"""
    print("\n" + "-" * 40 + "\nLFImap finished with execution.", flush = True)
    print("Parameters tested: " + str(stats["urls"]), flush = True)

    totalRequests = stats["requests"] + stats["getRequests"] + stats["postRequests"]
    print("Requests sent: " + str(totalRequests), flush = True)
    print("Vulnerabilities found: " + str(stats["vulns"]), flush = True)


init_stats()

