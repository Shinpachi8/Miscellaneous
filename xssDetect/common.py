#!/usr/bin/env python
# coding=utf-8

import json
import urlparse
import urllib

class Pollution(object):
    """
    this class aim to use the payload
    to the param in requests
    """
    def __init__(self, url, payloads, data=None, pollution_all=False, append=True):
        """
        :url: the url to parse, if get must had the params
        :payloads:  List, the payloads to added in params
        :data: if url is POST, the data is the post data
        """
        self.url = url
        self.payloads = payloads
        self.data = data
        self.json = False
        self.pollution_all = pollution_all
        self.append = append
        self.polluted_urls = []

        if type(self.payloads) != list:
            self.payloads = [self.payloads,]
        self.method = 'GET' if self.data is None else 'POST'

    def pollut(self):
        if (not self.url.startswith('http://')) and (not self.url.startswith('https://')):
            return
        if self.method == 'GET':
            parsed_url = Url.url_parse(self.url)
            #print "===================================="
            #print parsed_url
            query_string = parsed_url.query
        else:
            try:
                query_string = Url.build_qs(json.loads(self.data))
                self.json = True
            except:
                query_string = self.data
        if query_string is None:
            return
        #print query_string
        query_dict = Url.qs_parse(query_string)
        for key in query_dict.keys():
            for payload in self.payloads:
                tmp_qs = query_dict.copy()
                if self.append:
                    tmp_qs[key] = tmp_qs[key] + payload
                else:
                    tmp_qs[key] = payload
                tmp_qs_str = Url.build_qs(tmp_qs)
                if self.method == 'GET':
                    self.polluted_urls.append({'method': 'GET', 'url': Url.url_unparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path,    parsed_url.params, tmp_qs_str, parsed_url.fragment))})
                else:
                    # _['method'] = 'POST'
                    # _['url'] = self.url
                    # _['data'] = tmp_qs_str if not self.json else json.dumps(tmp_qs)
                    self.polluted_urls.append({
                        'method': 'POST',
                        'url': self.url,
                        'data': tmp_qs_str if not self.json else json.dumps(tmp_qs)
                    })

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



def addslashes(s):
    l = ['\\', '"', "'", "\0"]
    for i in l:
        if i in s:
            s = s.replace(i, '\\'+i)
    return s



def main():
    url = 'http://www.iqiyi.com/path1/?p1=v1&p2=v2'
    payloads = ['xss"<svg>', '../../../../../../../etc/passwd']
    print Pollution(url, payloads).payload_generate()

if __name__ == '__main__':
    main()
