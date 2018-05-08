#!/usr/bin/env python
#coding=utf-8


import threading
from lib.common import *
from classSQLTimeInjection import *


lock = threading.Lock()
class Monitor(threading.Thread):
    STOP_ME = False
    #plugins = []
    #STOP_ME = False
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
                url = task['url']
                headers = task['headers']
                data = task['data'] if 'data' in task else None
                try:
                    time_result = SQLInjectionTime(url, headers=headers, data=data).startTest()
                    if time_result:
                        with lock:
                            with open('sql_time_result.txt', 'a') as f:
                                f.write("[sqlinjection time] [awvs] {}".format(url))
                        logger.error("found sql_time injeciton:{}".format(url))
                except KeyboardInterrupt:
                    Monitor.STOP_ME = True
                except Exception as e:
                    logger.error("SqlI Time Error For: {} AT URL={}".format(repr(e), url))
           # if task:
           #     task = json.loads(task)

            else:
                logger.info("now, we have no task and sleep..")
                time.sleep(600)

        #if self.conn.is_connected:
        #    self.conn.close()


def main():
    threads = []
    for i in xrange(30):
        t = Monitor()
        t.setDaemon = True
        threads.append(t)

    for t in threads:
        t.start()

    while True:
        try:
            if threading.activeCount() <= 1:
                break
            #time.sleep(10)
        except KeyboardInterrupt:
            Monitor.STOP_ME = True
            print "user killed and ready to exit"
            break
        except Exception as e:
            logger.error("monitor.main error for {}".repr(e))

if __name__ == '__main__':
    main()

