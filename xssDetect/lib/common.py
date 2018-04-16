#!/usr/bin/env pytython
# coding=utf-8

"""
in here, we create some basic class to use like TURL, THTTPJOB, 
and some function like is_http and so on

"""
import urlparse
import ssl
import re
import json
import socket
import time
import httplib
import urllib
import requests
requests.packages.urllib3.disable_warnings()


STATIC_EXT = ["f4v","bmp","bz2","css","doc","eot","flv","gif"]
STATIC_EXT += ["gz","ico","jpeg","jpg","js","less","mp3", "mp4"]
STATIC_EXT += ["pdf","png","rar","rtf","swf","tar","tgz","txt","wav","woff","xml","zip"]


BLACK_LIST_PATH = ['logout', 'log-out', 'log_out']

class TURL(object):
    """docstring for TURL"""
    def __init__(self, url):
        super(TURL, self).__init__()
        self.url = url
        self.format_url()
        self.parse_url()
        if ':' in self.netloc:
            tmp = self.netloc.split(':')
            self.host = tmp[0]
            self.port = int(tmp[1])
        else:
            self.host = self.netloc
            self.port = 80
        if self.start_no_scheme:
            self.scheme_type()

        self.final_url = ''
        self.url_string()

    def parse_url(self):
        parsed_url = urlparse.urlparse(self.url)
        self.scheme, self.netloc, self.path, self.params, self.query, self.fragment = parsed_url

    def format_url(self):
        if (not self.url.startswith('http://')) and (not self.url.startswith('https://')):
            self.url = 'http://' + self.url
            self.start_no_scheme = True
        else:
            self.start_no_scheme = False

    def scheme_type(self):
        if is_http(self.host, self.port) == 'http':
            self.scheme = 'http'

        if is_https(self.host, 443) == 'https':
            self.scheme = 'https'
            self.port = 443

    @property
    def get_host(self):
        return self.host

    @property
    def get_port(self):
        return self.port

    @property
    def get_scheme(self):
        return self.scheme

    @property
    def get_path(self):
        return self.path

    @property
    def get_query(self):
        """
        return query
        """
        return self.query

    @property
    def get_dict_query(self):
        """
        return the dict type query
        """
        return dict(urlparse.parse_qsl(self.query))

    @get_dict_query.setter
    def get_dict_query(self, dictvalue):
        if not isinstance(dictvalue, dict):
            raise Exception('query must be a dict object')
        else:
            self.query = urllib.urlencode(dictvalue)

    @property
    def get_filename(self):
        """
        return url filename
        """
        return self.path[self.path.rfind('/')+1:]

    @property
    def get_ext(self):
        """
        return ext file type
        """
        fname = self.get_filename
        ext = fname.split('.')[-1]
        if ext == fname:
            return ''
        else:
            return ext

    def is_ext_static(self):
        """
        judge if the ext in static file list
        """
        if self.get_ext in STATIC_EXT:
            return True
        else:
            return False

    def is_block_path(self):
        """
        judge if the path in black_list_path
        """
        for p in BLACK_LIST_PATH:
            if p in self.path:
                return True
        else:
            return False

    def url_string(self):
        data = (self.scheme, self.netloc, self.path, self.params, self.query, self.fragment)
        url = urlparse.urlunparse(data)
        self.final_url = url
        return url

    def __str__(self):
        return self.final_url

    def __repr__(self):
        return '<TURL for %s>' % self.final_url



class THTTPJOB(object):
    """docstring for THTTPJOB"""
    def __init__(self, 
                url, 
                method='GET', 
                data=None, 
                files=False,
                filename='',
                filetype='image/png',
                headers=None, 
                block_static=True, 
                block_path = True,
                allow_redirects=False, 
                verify=False,
                timeout = 10,
                is_json=False,
                time_check=True):
        """
        :url: the url to requests,
        :method: the method to request, GET/POST,
        :data: if POST, this is the post data, if upload file, this be the file content
        :files: if upload files, this param is True
        :filename: the upload filename
        :filetype: the uplaod filetype
        :headers: the request headers, it's a dict type,
        :block_static: if true, will not request the static ext url
        :block_path: if true, will not request the path in BLOCK_LIST_PATH
        :allow_redirects: if the requests will auto redirects
        :verify: if verify the cert
        :timeout: the request will raise error if more than timeout
        :is_json: if the data is json
        :time_check: if return the check time
        """
        super(THTTPJOB, self).__init__()
        if isinstance(url, TURL):
            self.url = url
        else:
            self.url = TURL(url)

        self.method = method
        self.data = data
        self.files = files
        self.filename = filename
        self.filetype = filetype
        self.block_path = block_path
        self_headers = {
            'User-Agent': ('Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko)'
                'Chrome/38.0.2125.111 Safari/537.36 IQIYI Cloud Security Scanner tp_cloud_security[at]qiyi.com'),
            'Connection': 'close',
        }
        self.headers = headers if headers else self_headers
        self.block_static = block_static
        self.allow_redirects = allow_redirects
        self.verify = verify
        self.timeout = timeout

        
    def request(self):
        """
        return status_code, headers, htmlm, time_check
        """
        if self.block_static and self.url.is_ext_static():
            return -1, {}, '', 0
        elif self.block_path and self.url.is_block_path():
            return -1, {}, '', 0
        else:
            start_time = time.time()
            try:
                if self.method == 'GET':
                    self.response = requests.get(
                        self.url.url_string(),
                        headers = self.headers,
                        allow_redirects = self.allow_redirects,
                        verify = self.verify,
                        timeout = self.timeout,
                        )
                    end_time = time.time()
                else:
                    if not self.files:
                        self.response = requests.post(
                            self.url.url_string(),
                            data = self.data,
                            headers = self.headers,
                            verify = self.verify,
                            allow_redirects = self.allow_redirects,
                            timeout = self.timeout,
                            )
                    else:
                        # print "------------------"
                        f = {'file' : (self.filename, self.data, self.filetype)}
                        self.response = requests.post(
                            self.url.url_string(),
                            files=f,
                            headers=self.headers,
                            verify=False,
                            allow_redirects=self.allow_redirects,
                            # proxies={'http': '127.0.0.1:8080'},
                            timeout=self.timeout,
                            )
                    end_time = time.time()
            except Exception as e:
                print "[lib.common] [THHTPJON.request] {}".format(repr(e))
                end_time = time.time()
                return -1, {}, '', 0
            self. time_check = end_time - start_time
            return self.response.status_code, self.response.headers, self.response.text, self.time_check





def is_http(url, port=None):
    """
    judge if the url is http service
    :url  the host, like www.iqiyi.com, without scheme
    """
    if port is None: port = 80
    service = ''
    try:
        conn = httplib.HTTPConnection(url, port, timeout=10)
        conn.request('HEAD', '/')
        conn.close()
        service = 'http'
    except Exception as e:
        print "[lib.common] [is_http] {}".format(repr(e))

    return service

def is_https(url, port=None):
    """
    judge if the url is https request
    :url  the host, like www.iqiyi.com, without scheme
    """
    ssl._create_default_https_context = ssl._create_unverified_context
    if port is None: port = 443
    service = ''
    try:
        conn = httplib.HTTPSConnection(url, port, timeout=10)
        conn.request('HEAD', '/')
        conn.close()
        service = 'https'
    except Exception as e:
        print "[lib.common] [is_http] {}".format(repr(e))

    return service



class Pollution(object):
    """
    this class aim to use the payload
    to the param in requests
    """
    def __init__(self, query, payloads, pollution_all=False, isjson=False):
        """
        :query: the url query part
        :payloads:  List, the payloads to added in params
        :data: if url is POST, the data is the post data
        """
        self.payloads = payloads
        self.query = query
        self.isjson = isjson
        self.pollution_all = pollution_all
        self.polluted_urls = []

        if type(self.payloads) != list:
            self.payloads = [self.payloads,]

    def pollut(self):
        if self.isjson:
            query_dict = json.loads(self.query)
        else:
            query_dict = dict(urlparse.parse_qsl(self.query, keep_blank_values=True))
    
        for key in query_dict.keys():
            for payload in self.payloads:
                tmp_qs = query_dict.copy()
                tmp_qs[key] = tmp_qs[key] + payload
                self.polluted_urls.append(tmp_qs)

    def payload_generate(self):
        print self.payloads
        if self.pollution_all:
            pass
        else:
            self.pollut()
            return self.polluted_urls






class Url:

    @staticmethod
    def url_parse(url):
        return urlparse.urlparse(url)

    @staticmethod
    def url_unparse(data):
        scheme, netloc, url, params, query, fragment = data
        if params:
            url = "%s;%s" % (url, params)
        return urlparse.urlunsplit((scheme, netloc, url, query, fragment))

    @staticmethod
    def qs_parse(qs):
        return dict(urlparse.parse_qsl(qs, keep_blank_values=True))

    @staticmethod
    def build_qs(qs):
        return urllib.urlencode(qs).replace('+', '%20')

    @staticmethod
    def urldecode(qs):
        return urllib.unquote(qs)

    @staticmethod
    def urlencode(qs):
        return urllib.quote(qs)

if __name__ == '__main__':
    file = 'img.png'
    filetype='image/png'
    data="data"

    hj2 = THTTPJOB('www.iqiyi.com', method='POST', files=True, filename=file, data=data)
    hj2.request()
    assert hj2.response.status_code == 200

    xss = [
        "\" onfous=alert(document.domain)\"><\"",
        "\"`'></textarea><audio/onloadstart=confirm`1` src>",
        "\"</script><svg onload=alert`1`>",
        # "\"`'></textarea><audio/onloadstart=confirm`1` src>",
    ]

    url = 'http://www.iqiyi.com/path/?p=v&p2=v2'
    query = 'p=v&p2=v2'
    print Pollution(query, xss).payload_generate()