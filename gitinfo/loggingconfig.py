#!/usr/bin/env python
# coding=utf-8

import logging

# referer:  http://www.jianshu.com/p/feb86c06c4f4
# create logger
logger = logging.getLogger("test")

# create handler
filehandler = logging.FileHandler("logtest.log", mod="w", encoding="utf-8", delay=False)
streamhandler = logging.StreamHandler()

# create format
formatter = logging.Formatter("[%(asctime)s] [%(filename)s] [%(lineno)d] %(message)s")

# add formatter to handler
filehandler.setFormater(formatter)
streamhandler.setFormater(formatter)

# set hander to logger
logger.addHandler(filehandler)
logger.addHandler(streamhandler)

