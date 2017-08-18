#!/usr/bin/env python
# coding=utf-8

import requests
import json
import urllib
from urlparse import urljoin

# start sqlmapapi
# in here, default sqlmapapi is start ,so here only some method to use
# TODO://  made a server method, and return the default admin_id and sqllite database instead of default random admin_id and database
# Maybe I should turn it to staticClass
# TODO:// NEED to add loggiing...


headers = {
    "User-Agent" : "no mattern what",
    "Content-Type" : "application/json",
    "Connection" : "close"
    }

class AutoSqli:
    def __init__(self, url, target, data=None, cookie=None,  options=None):
        # sqlmapapi server address
        self.url = url
        # potential target 
        self.target = target
        self.cookie = cookie
        # if post, need data
        self.data = (data)
        # self define options, format is "level=3,delay=1,", i.e. split by ','
        self.options = options
        self.taskId = ""
        
    
    def createNewTask(self):
        # this function is for create a taskId
        path = "task/new"
        _url = urljoin(self.url, path)
        print _url
        try:
            response = requests.get(_url, headers=headers)
            print response.text
            self.taskId = response.json()["taskid"]
            return self.taskId
        except Exception, e:
            raise
    
    def optionSet(self):
        # this function is to start a Task, default option is
        # level=3 tamper=space2comment delay=1
        _data = {"url": self.target, }
        default_options = {"level": "3", "delay": "1", "tamper":"space2comment",
                            "skipStatic": True, "smart": True}
        # if post data
        if self.data:
            _ = {"data": (self.data)}
            _data = dict(_data, **_)
        if self.cookie:
            _ = {"cookie": self.cookie}
            _data = dict(_data, **_)
        
        # if self.option is not None
        
        if self.options:
            options = {}
            for _ in self.options.split(","):
                key, value = _.split("=")[0], _.split("=")[1]
                options[key] = value
            _data = dict(_data, **options)
        else:
            _data = dict(_data, **default_options)
        #print _data
        
        # startPath
        path = "option/{}/set".format(self.taskId)
        _url = urljoin(self.url, path)
        #print _url
        #print _data
        try:
            response = requests.post(_url, data=json.dumps(_data), headers=headers)
            #print response.text
            if response.json()["success"] == "true":
                return True
            else:
                return False
        except Exception, e:
            return False
    
    
    @staticmethod
    def checkResult(url, taskId):
        # in here, we define that 
        # 1 -> Terminal and Vulnerable
        # 2 -> Terminal and Not Vulnerable
        # 3 -> Not Terminal
        # 4 -> Error Happend
        path = "scan/{}/status".format(taskId)
        _url = urljoin(url, taskId)
        try:
            response = requests.get(_url, headers)
            _ = response.json()
            if _["status"] == "terminated":
                # todo check data
                cdpath = "scan/{}/data".format(taskId)
                _cdurl = urljoin(url, cdpath)
                if AutoSqli.checkData(_cdurl):
                    return 1
                else:
                    return 2
            else:
                return 3
        except Exception, e:
            return 4
    
    @staticmethod
    def checkData(url):
        try:
            _ = requests.get(url, headers=headers)
            if _.json()["data"]:
                return True
            else:
                return False
        except Exception, e:
            return False
            
        
        
