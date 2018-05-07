#!/usr/bin/env python
#coding=utf-8


import threading
from lib.common import *



lock = threading.Lock()
class Monitor(threading.Thread):
    STOP_ME = False
    plugins = []
    STOP_ME = False
    def __init__(self):
        threading.Thread.__init__(self)
        self.conn = RedisUtil(REDIS_DB, REDIS_HOST, REDIS_PASSWORD)

    def run(self):
        while True:
            if Monitor.STOP_ME:
                break

            # with lock:
            #     if plugin_num != len(Monitor.plugins):
            #         Monitor.plugins = importpoc()

            task = None
            with lock:
                task = self.conn.task_fetch(SQLI_TIME_QUEUE)
            
            if task:
                task = json.loads(task)
                for p in Monitor.plugins:
                    (result, message) = p(task)
                    if result:
                        # save to mysql
                        logger.info("[found] Message={}".format(message))
            else:
                logger.info("now, we have no task and sleep..")
                time.sleep(600)
        
        if self.conn.is_connected:
            self.conn.close()