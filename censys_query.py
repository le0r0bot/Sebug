import requests
import json
from Queue import Queue
import threading
import sys
import time

API_URL = "https://www.censys.io/api/v1"
UID = ""
SECRET = ""
PAGES = 28
cur_page = 1

vul_ip = open("test_ip.txt","w")

def get_ip(query,page):
    data = {
        "query":query,
        "page":page,
        "fields":["ip"]
    }

    try:
        res = requests.post(API_URL + "/search/ipv4",data=json.dumps(data),auth=(UID,SECRET))
        results = res.json()
        if res.status_code != 200:
            print "Error : %s" % results["error"]
            sys.exit(1)
        else:
            result_iter = iter(results["results"])
            for result in result_iter:
                vul_ip.write(result["ip"] + "\n")
    except Exception,e:
        print e


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print """
Usage:
    python censys_query.py query_str
                """
        sys.exit()
    else:
        query = sys.argv[1]

        while cur_page <= PAGES:
            print "Page" + str(cur_page)
            get_ip(query,cur_page)
            cur_page += 1
            time.sleep(1)
        vul_ip.close()