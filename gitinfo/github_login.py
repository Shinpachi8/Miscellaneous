#!/usr/bin/env python
# coding=utf-8

import requests
import random
from bs4 import BeautifulSoup as bs

requests.packages.urllib3.disable_warnings()

user_agents = [
    # 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/9.0.3 Safari/7046A194A',
    'Opera/9.80 (X11; Linux i686; Ubuntu/14.10) Presto/2.12.388 Version/12.16',
    'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/50.1',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.19 (KHTML, like Gecko) Ubuntu/11.10 Chromium/18.0.1025.142 Chrome/18.0.1025.142 Safari/535.19',
]


def login():
    headers = {
        "User-Agent": 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36',
        "Origin": "https://github.com",
        "Referer": "https://github.com/",
        "Connection": "Keep-Alive",
    }
    username = "@163.com"
    password = "!1"

    base_url = "https://github.com"
    session = requests.Session()
    session.headers.update(headers)
    try:
        resp = session.get("https://github.com/login", verify=False)
        html = resp.text
        soup = bs(html, "html.parser")
        login_div = soup.find_all("form")[0]
        login_url = base_url + "/session"
        print login_url + "\n #####################"
        inputs = login_div.find_all("input")
        data = {}
        # headers["Cookie"] = resp.headers["Set-Cookie"]
        for i in inputs:
            # assert(hasattr(i, "value"))
            name = i["name"]

            value = i["value"] if i.has_attr("value") else ""
            data[name] = value
            # print "name:\t{}, value:{}".format(name, value)

        data["login"] = username
        data["password"] = password
        # session.headers.update(headers)
        resp = session.post(login_url, data=data, verify=False)
        if resp.status_code in [200, 302]:
            a = session.get("https://github.com/dmitryz/ticketbot/contributors/a6607e29de2335020978cab68c01f47528fbd306/mail.rb")
            cc = update(a, a.request.headers)
            return a.request.headers["Cookie"]
            # return session
        else:
            return None
    except Exception as e:
        print "[Error] [github_login] " + repr(e)
        return None
    # headers["Cookie"] = resp.headers["Set-Cookie"]
    # print resp.headers
    # print "------------------"
def update(response, headers):
    s = response.headers["Set-Cookie"]
    # print s
    gh_sess =  [x for x in list(set(s.split(","))) if x.find("_gh_sess") > 0]

    if not gh_sess:
        print gh_sess
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
        return updated_cookie

if __name__ == '__main__':
    headers = login()
    # print headers
    #_octo=GH1.1.1985934553.1505834380; logged_in=yes; dotcom_user=viewer2015; user_session=gETz7G7tqReB__HSWOZeFrZwzHo3rego-gM2DArFZX16w3jW; __Host-user_session_same_site=gETz7G7tqReB__HSWOZeFrZwzHo3rego-gM2DArFZX16w3jW; _gh_sess=eyJsYXN0X3dyaXRlIjoxNTA1OTA4NDc2NzQ5LCJzZXNzaW9uX2lkIjoiNjkwNWU1Y2E5NjE2Yjg4ZmRhNjkzYzljNjhjYTIyOTAiLCJsYXN0X3JlYWRfZnJvbV9yZXBsaWNhcyI6MTUwNTk4MjkyMjk4Niwic3B5X3JlcG8iOiJyaW5nMDRoL3BhcGVycyIsInNweV9yZXBvX2F0IjoxNTA1OTIxNzU3LCJjb250ZXh0IjoiLyIsImZsYXNoIjp7ImRpc2NhcmQiOlsiYW5hbHl0aWNzX2xvY2F0aW9uIl0sImZsYXNoZXMiOnsiYW5hbHl0aWNzX2xvY2F0aW9uIjoiL2Rhc2hib2FyZCJ9fX0%3D--afa300ef4905c21803df2afd9e331aa0b19c324c; _ga=GA1.2.1722114177.1505834380; _gat=1; tz=Asia%2FShanghai"

    #_ga=GA1.2.1722114177.1505834380; _gat=1; tz=Asia%2FShanghai"
    # # print session
    # s= "user_session=tFmYMb2G60_Yscc_ZZhEPSvbOcLHsgoOt2cwLts4X7mit2jz; path=/; expires=Thu, 02 Nov 2017 08:03:24 -0000; secure; HttpOnly, __Host-user_session_same_site=tFmYMb2G60_Yscc_ZZhEPSvbOcLHsgoOt2cwLts4X7mit2jz; path=/; expires=Thu, 02 Nov 2017 08:03:24 -0000; secure; HttpOnly; SameSite=Strict, _gh_sess=eyJsYXN0X3dyaXRlIjoxNTA4NDAwMjAzMTM0LCJzZXNzaW9uX2lkIjoiNTMyMDAwZGU3MGRlZGNhMDE0M2Q1NGQyYzk4MWVkYjAiLCJjb250ZXh0IjoiLyIsImxhc3RfcmVhZF9mcm9tX3JlcGxpY2FzIjoxNTA4NDAwMjA0MDk0LCJzcHlfcmVwbyI6ImRtaXRyeXovdGlja2V0Ym90Iiwic3B5X3JlcG9fYXQiOjE1MDg0MDAyMDR9--3d2d46b9ac2c616c39ee0f90c76ad3f179e4ea85; path=/; secure; HttpOnly"
    # gh_sess =  [x for x in list(set(s.split(","))) if x.find("_gh_sess") > 0][0]
    # print gh_sess
    # headers={
    #     'User-Agent' : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0',
    #     "Accept-Language" : "zh-CN,zh;q=0.8,zh-TW;q=0.3",
    #     "Accept" : "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    #     "Cache-Control" : "no-cache",
    #     "Connection" : "keep-alive",
    #     "Cookie" : "_octo=GH1.1.1985934553.1505834380; logged_in=yes; dotcom_user=viewer2015; user_session=gETz7G7tqReB__HSWOZeFrZwzHo3rego-gM2DArFZX16w3jW; __Host-user_session_same_site=gETz7G7tqReB__HSWOZeFrZwzHo3rego-gM2DArFZX16w3jW; _gh_sess=eyJsYXN0X3dyaXRlIjoxNTA1OTA4NDc2NzQ5LCJzZXNzaW9uX2lkIjoiNjkwNWU1Y2E5NjE2Yjg4ZmRhNjkzYzljNjhjYTIyOTAiLCJsYXN0X3JlYWRfZnJvbV9yZXBsaWNhcyI6MTUwNTk4MjkyMjk4Niwic3B5X3JlcG8iOiJyaW5nMDRoL3BhcGVycyIsInNweV9yZXBvX2F0IjoxNTA1OTIxNzU3LCJjb250ZXh0IjoiLyIsImZsYXNoIjp7ImRpc2NhcmQiOlsiYW5hbHl0aWNzX2xvY2F0aW9uIl0sImZsYXNoZXMiOnsiYW5hbHl0aWNzX2xvY2F0aW9uIjoiL2Rhc2hib2FyZCJ9fX0%3D--afa300ef4905c21803df2afd9e331aa0b19c324c; _ga=GA1.2.1722114177.1505834380; _gat=1; tz=Asia%2FShanghai",
    #     "Referer" : "https://github.com/",
    #     "Upgrade-Insecure-Requests" : "1"
    #     }


    # origin_cookie = headers["Cookie"]
    # origin_cookie = origin_cookie.split(";")
    # updated_cookie = ""
    # for i in origin_cookie:
    #     if i.find("_gh_sess") > 0:
    #         updated_cookie += gh_sess
    #     else:
    #         updated_cookie += i
    #     updated_cookie += ";"

    # headers["Cookie"] = updated_cookie
    # print headers
