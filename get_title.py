#!/usr/bin/env python
# coding=utf-8


import requests
import sys
import os
import threading
import re
from Queue import Queue


domain_queue = Queue()
title_queue = Queue()
lock = threading.Lock()



headers = {
    'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0',
}
pattern = re.compile('<title>(.*)?</title>')
pattern2 = re.compile('<h1>(.*)?</h1>')

def read_file(filename):
    if not os.path.exists(filename):
        raise Exception('The file is not exists')

    with open(filename, 'r') as f:
        for line in f.xreadlines():
            line = line.strip()
            domain_queue.put(line)


def write2file(msg):
    with open('domain-title.txt', 'a') as f:
        f.write(msg + "\n")


def fetch_title(queue):
    while True:
        if queue.empty():
            break
        print "still remains {} items".format(queue.qsize())
        domain = queue.get()
        url = 'http://' + domain
        url2 = 'https://' + domain
        urllist = [url, url2]
        for url in urllist:
            try:
                html1 = requests.get(url, headers=headers, verify=False).content
                title = pattern.findall(html1)
                if title:
                    msg = '[{title}]({url})'.format(title=title[0], url=url)
                    with lock:
                        write2file(msg)
                    # title_queue.put(msg)
                else:
                    h1 = pattern2.findall(html1)
                    if h1:
                        msg = '[{title}]({url})'.format(title=title[0], url=url)
                        with lock:
                            write2file(msg)
                        # title_queue.put(msg)
            except Exception as e:
                # with lock:
                #     ErrorCount += 1
                print repr(e)

def main():
    # ErrorCount = 0
    # global ErrorCount
    threads = []

    filename = sys.argv[1]

    read_file(filename)

    for i in xrange(20):
        t = threading.Thread(target=fetch_title, args=(domain_queue,))
        threads.append(t)

    for t in threads:
        t.start()

    for t in threads:
        t.join()

    # titlelist = []
    # while not title_queue.empty():
    #     i = title_queue.get()
    #     titlelist.append(i)

    # write2file(titlelist)

if __name__ == '__main__':
    main()
