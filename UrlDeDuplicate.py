#!/usr/bin/env python
# coding=utf-8


import urlparse
import urllib


def isascii(s):
    return all([ord(i) < 128 for i in s])

class UrlPattern(object):
    def __init__(self, url):
        self.url = url
        self.parsed_url = urlparse.urlparse(url)

    def get_query_pattern(self):
        query = self.parsed_url.query
        if not query:
            return ''
        
        query_dict = dict(urlparse.parse_qsl(query))
        for key in query_dict:
            # if int
            value = query_dict[key]
            value = urllib.unquote(value)
            if value.isdigit():
                query_dict[key] = '{digit}'
            elif value.isalpha():
                query_dict[key] = '{alpha}'
            elif isascii(value):
                query_dict[key] = '{ascii}'
            else:
                query_dict[key] = '{no_ascii}'
        return urllib.urlencode(query_dict)
    

    def get_path_pattern(self):
        path = self.parsed_url.path
        ext = ''
        pattern = []
        if '.' in path:
            ext = path[path.rindex('.'):]
            path = path.replace(ext, '')
  
        # 这三个应该够了
        flags = '/_-' 
        path = urllib.unquote(path)
        dirs = path.split('/')
        print dirs
        for d in dirs:
            if not d:
                continue
            has_flag = False
            for flag in flags:
                if flag in d:
                    has_flag = True
                    split_dir = d.split(flag)
                    print split_dir
                    tmp_pattern  = []
                    for s in split_dir:
                        if not s:
                            continue
                        if s.isdigit():
                            tmp_pattern.append('{digit}')
                        elif s.isalpha():
                            tmp_pattern.append('{' + str(len(s)) + 'alpha}')
                        elif isascii(s):
                            tmp_pattern.append('{' + str(len(s)) + 'ascii}')
                        elif not isascii(s):
                            tmp_pattern.append('{no_ascii}')
                        else:
                            tmp_pattern.append(s)
                    pattern.append(flag.join(tmp_pattern)) 
                    
            if not has_flag:
                if d.isdigit():
                    pattern.append('{digit}')
                elif not isascii(d):
                    pattern.append('{no_ascii}')
                else:
                    pattern.append(d)
        s = '/'.join(pattern) + ext
        print s
        return s

    def get_pattern(self):
        query = self.get_query_pattern()
        path = self.get_path_pattern()
        netloc = self.parsed_url.netloc
        scheme =self.parsed_url.scheme

        return urlparse.urlunparse((scheme, netloc, path, '', query, ''))


def main():
    # url = 'https://passport.jd.com/uc/login?ReturnUrl=http://security.jd.com/#/'
    # url = 'http://www.iqiyi.com/v_19rr1eiivs.html'
    # url = 'http://www.iqiyi.com/v_19rr1vzhxw.html?list=19rrliqko6'
    # url = 'http://so.iqiyi.com/so/q_%E8%8A%B8%E6%B1%90%E4%BC%A0?refersource=lib'
    url = 'http://list.iqiyi.com/www/31/-27507------------11-1--iqiyi--.html'
    print UrlPattern(url).get_pattern()

if __name__ == '__main__':
    main()

