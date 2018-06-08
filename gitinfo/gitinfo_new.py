#!/usr/bin/env python
# coding=utf-8

import time
import logging
import requests
import hashlib
from github_login import *
from time import sleep
import json
import random
import datetime
from bs4 import BeautifulSoup as bs
from scanwork import *
from sqlalchemy_gitinfo import *
from common import *

requests.packages.urllib3.disable_warnings()
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
                    datefmt='%m-%d %H:%M',
                    filename='githubinfo.log',
                    filemode='w')
# logging.getLogger().setLevel(logging.DEBUG)
# requests_log = logging.getLogger("requests.packages.urllib3")
# requests_log.setLevel(logging.INFO)







def update_cookie(response):
    s = response.headers["Set-Cookie"]
    # print s
    gh_sess =  [x for x in list(set(s.split(","))) if x.find("_gh_sess") > 0]

    if not gh_sess:
        return False
    else:
        gh_sess = gh_sess[0]
        origin_cookie = headers["Cookie"]
        origin_cookie = origin_cookie.split(";")
        updated_cookie = ""
        for i in origin_cookie:
            if i.find("_gh_sess") > 0:
                updated_cookie += gh_sess
            else:
                updated_cookie += i
            updated_cookie += ";"

        headers["Cookie"] = updated_cookie
        return True


def getHtmlSummary(url):
    # logging.info("headers:\t" + str(headers))

    if url.find("raw.githubusercontent.com") > 0:
        tmp_headers = raw_headers
    else:
        tmp_headers = headers

    tmp_headers["User-Agent"] = get_randomUA()
    try:
        pr = random_proxy()
        assert pr != ""
        proxy = {pr[0].lower() : pr[0]+ "://" + pr[1] }
        page = requests.get(url, headers=tmp_headers, verify=False, timeout=20, proxies=proxy)
    except Exception as e:
        page = requests.get(url, headers=tmp_headers, verify=False, timeout=20)

    # print page.headers
    if "Set-Cookie" in page.headers:
        if update_cookie(page):
            logging.info("update cookie success")
        else:
            logging.info("failed with update cookie")
    content = page.text
    return content


def pickemail(url):
    logging.info("pickemail at url:\t" + url)
    try:
        htmlDetail = getHtmlSummary(url)
    except Exception as e:
        return
    mail1 = reg_emails1.findall(htmlDetail)
    mail2 = reg_emails2.findall(htmlDetail)

    mail = mail1 + mail2
    mail = [m.replace('""', '').replace('\'', '') for m in mail]
    mail = list(set([m for m in mail if m.split("@")[-1] in domains]))
    if mail:
        print "[found mails= {}\n]".format(mail)
    if mail:
        sqlal = SqlOpt()
        #logging.info("date: {}  mail:{}".format(getTime(), mail))
        hashs = get_md5(url)
        if sqlal.query_visit(hashs):
            sqlal.close()
            return
        else:
            try:
                sqlal.insert_visit(hashs, url)
            except Exception as e:
                logging.error("[-] [Error] [Line 102]SqlAlchemy Insert VisitInfo Failed " + repr(e))
        time = getTime()
        email = ",".join(mail)
        #email = email.replace("'", "").replace('"', "")
        send_mail(url, email)
        # def insert_info(self, hashvalue, url, email, time, checked=0):
        try:
            sqlal.insert_info(hashs, url, email, time)
        except Exception as e:
            info = "{}:{}:{}:{}".format(hashs, url, email, time)
            write_file("insert_info_error_with_email.txt", info)
        sqlal.close()




#后期改成三组，分别为python, php, text 语言的.
def gitinfo_scan():

    thread_pool = ThreadPoolManager(8)
    Cookie = login()
    if Cookie is None:
        return

    headers["Cookie"] = Cookie
    htmlSummaryList = [
       "https://github.com/search?o=desc&p={}&q=smtp+pass+mail&l=Java&s=indexed&type=Code&utf8=%E2%9C%93&_pjax=%23js-pjax-container",
       "https://github.com/search?o=desc&p={}&q=smtp+pass+mail&l=Python&s=indexed&type=Code&utf8=%E2%9C%93&_pjax=%23js-pjax-container",
       "https://github.com/search?o=desc&p={}&q=smtp+pass+mail&l=PHP&s=indexed&type=Code&utf8=%E2%9C%93&_pjax=%23js-pjax-container",
       "https://github.com/search?o=desc&p={}&q=smtp+pass+mail&l=INI&s=indexed&type=Code&utf8=%E2%9C%93&_pjax=%23js-pjax-container",
        ]

    # qq_163_mails = set()
    for index, html in enumerate(htmlSummaryList):
        count_add_queue = 0
        x = range(1,80)
        # random.shuffle(x)
        for i in x:
            logging.info("[fetching] " + html.format(i))
            #global headers
            headers["Referer"] = html.format(i)
            # logging.info("request.headers = {}".format(headers))
            try :
                htmlSummary = getHtmlSummary(html.format(i))

                if "You have triggered an abuse detection mechanism." in htmlSummary and "Please wait a few minutes before you try again" in htmlSummary:
                    logging.info("your ip has been baned by github")
                    time.sleep(60*3)
                urllist = getHtmlurl(htmlSummary)
            except Exception as e:
                logging.info("[-][Error] Line 145.\t" +  repr(e))
                continue
            # print urllist
            for url in urllist:
                try:
                    if 'blob' in url:
                        url = url.split('blob/')[0] + url.split('blob/')[1]
                    else:
                        # print "blob not in: {}".format(url)
                        continue
                    url = "https://raw.githubusercontent.com" + url
                    # print "[+] Parsing Url:\t" + url
                    thread_pool.add_job(pickemail, url)
                    count_add_queue += 1

                except Exception as e:
                    logging.info("[main] [Error]" + repr(e))
            # print time.ctime() + "\tcount_add_queue:\t{}".format(count_add_queue)
            time.sleep(random.randint(1, 5))
        print "Add {} item in url: [{}]".format(count_add_queue, html.format(1))

    thread_pool.start_work()
    thread_pool.work_queue.join()


if __name__ == '__main__':
    load_proxy(sure=False)
    while True:
        gitinfo_scan()
        #a = random.randint(1, 5)
        time.sleep(60 * 60 * 3)

