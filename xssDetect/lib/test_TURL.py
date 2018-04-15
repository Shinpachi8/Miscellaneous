#!/usr/bin/env python
# coding=utf-8

from common import TURL
from common import THTTPJOB

def TestTURL():
    url = TURL('http://www.iqiyi.com/path1/index.php?p=v#top')
    assert url.get_ext == 'php'
    assert url.get_filename == 'index.php'
    assert url.get_path == '/path1/index.php'
    assert url.query == 'p=v'
    assert url.get_dict_query == {'p':'v'}
    url.get_dict_query = {'m':'p'}
    assert url.get_host == 'www.iqiyi.com'
    # print url.final_url
    assert url.url_string() == 'http://www.iqiyi.com/path1/index.php?m=p#top'

    url = 'http://store.iqiyi.com/category/203/?_page=1&_size=35&type=2'
    hj = THTTPJOB('http://www.iqiyi.com/')
    hj.request()
    assert hj.response.status_code == 200
    hj.url.get_dict_query = {'_page':2,'_size':15,'type':2}
    hj.request()
    # assert hj.response.url == url
    assert hj.response.status_code == 200
    file = 'img.png'
    filetype='image/png'
    data="data"

    hj2 = THTTPJOB('www.iqiyi.com', method='POST', files=True, filename=file, data=data)
    hj2.request()
    assert hj2.response.status_code == 200