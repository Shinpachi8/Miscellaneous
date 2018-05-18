#!/usr/bin/env python
# coding=utf-8

import threading
import random
from Queue import Queue

lock = threading.Lock()

class ThreadPoolManager():
    def __init__(self, thread_num):
        self.work_queue = Queue()
        self.thread_num = thread_num
        self.threads = []
        self._init_thread_pool(self.thread_num)

    def _init_thread_pool(self, thread_num):
        # 初始化线程池
        for i in range(thread_num):
            thread = ThreadManger(self.work_queue)
            self.threads.append(thread)

    def add_job(self, func, *args):
        self.work_queue.put((func, args))

    def start_work(self):
        for thd in self.threads:
            thd.start()
        # self.work_queue.join()


class ThreadManger(threading.Thread):
    def __init__(self, work_queue):
        threading.Thread.__init__(self)
        self.work_queue = work_queue
        self.daemon = True

    def run(self):
        while True:
            target, args = self.work_queue.get()
            target(*args)
            self.work_queue.task_done()


if __name__ == '__main__':
    def ad(a, b):
        print "a+b:\t" + str(a + b) + "\n"


    pool = ThreadPoolManager(4)
    for i in range(100):
        pool.add_job(ad, random.randint(1,9), random.randint(10,21))

    print pool.work_queue.qsize()
    pool.start_work()
    pool.work_queue.join()