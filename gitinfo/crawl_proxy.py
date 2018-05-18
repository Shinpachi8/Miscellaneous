#!/usr/bin/env python
#coding=utf-8



import requests
import threading
import time
from Queue import Queue
from bs4 import BeautifulSoup

"""
@author shinpachi8
@date   17/04/07
@describe

从西刺代理(IP84)上爬160页的代理 ，并用100个线程去验证
最后结果写入valid_proxy.txt

"""
inqueue = Queue()
inqueue_2 = Queue()
outqueue = Queue()

crawl_headers = {
    "User-Agent" : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.98 Safari/537.36",
    "Connection" : "close"
}

def xici_crawl():
    # 代理爬取的代码， xici
    # of = open('xici_proxy.txt' , 'w')
    for page in range(1, 100):
        try:
            html_doc = requests.get('http://www.xicidaili.com/nn/' + str(page), headers=crawl_headers ).content
            soup = BeautifulSoup(html_doc, "html.parser")
            trs = soup.find('table', id='ip_list').find_all('tr')
            for tr in trs[1:]:
                tds = tr.find_all('td')
                ip = tds[1].text.strip()
                port = tds[2].text.strip()
                protocol = tds[5].text.strip()
                if protocol in ['HTTP', 'HTTPS']:
                    inqueue.put('%s=%s:%s\n' % (protocol, ip, port))
                    # of.write('%s=%s:%s\n' % (protocol, ip, port) )
                    print '%s=%s:%s' % (protocol, ip, port)
            time.sleep(1)
        except Exception as e:
            print str(e)

def test():
    # 代理验证的代码
    while not inqueue_2.empty():
        proxy_line = inqueue_2.get()
        protocol, proxy = proxy_line.split("=")
        pr = {protocol.lower(): protocol.lower() + "://" + proxy.strip(),}
        # print pr
        try:
            # 延时5s
            res = requests.get("http://ip.cn/", headers=crawl_headers, timeout=5.0, proxies=pr)
            if res.status_code == 200:
            # lock.acquire()
                print proxy + "[ok!]"
                outqueue.put(protocol + "://" + proxy)
            # lock.release()
        except Exception, e:
            pass


def valid_proxy():
    # 写入代理到文件
    crawl_time = time.time()
    print "[+] Start Crawl Proxy..."
    xici_crawl()
    print "[+] Crawl Proxy Done. Use :\t {} s".format((time.time() - crawl_time))
    with open("proxies.txt", "w") as f:
        while not inqueue.empty():
            proxy = inqueue.get()
            f.write(proxy + "\n")
            inqueue_2.put(proxy)

    print "[+] Now Start Test Valid....."

    threads = []
    valid_time = time.time()
    for i in range(100):
        t = threading.Thread(target=test)
        threads.append(t)
        t.start()

    for thread in threads:
        thread.join()


    with open("valid_proxy.txt", "w") as fp:
        while not outqueue.empty():
            fp.write(outqueue.get().strip() + "\n")

    valid_end = time.time()
    print "[+] Test Valid Use :\t {}s".format((valid_end - valid_time) / 1000)
    print "[*Done]"


