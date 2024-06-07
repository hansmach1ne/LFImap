from src.utils.arguments import logging

stats = {}
stats["getRequests"] = 0
stats["postRequests"] = 0
stats["requests"] = 0
stats["info"] = 0
stats["vulns"] = 0
stats["urls"] = 0

# Function that will calculate statistics and print out the numbers
def printStats():
    # Print stats
    logging.info("\n" + '-'*40 + "\nLFImap finished with execution.")
    logging.info("Parameters tested: " + str(stats["urls"]))

    totalRequests = stats["requests"] + stats["getRequests"] + stats["postRequests"]
    logging.info("Requests sent: " + str(totalRequests))
    logging.info("Vulnerabilities found: " + str(stats["vulns"]))
