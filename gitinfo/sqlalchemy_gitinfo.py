#!/usr/bin/env python
# coding=utf-8

from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import *

DB_URI = "mysql://root@127.0.0.1/githubscan"

# 返回Table表属性的元类，和mapper

Base = declarative_base()
# 创建Engine对象, 参数为传的DSN
engine = create_engine(DB_URI)

# bind的engine的元信息，包括其中的数据库表
metadata = MetaData(bind=engine)

session_factory = sessionmaker(bind=engine)
Session = scoped_session(session_factory)

class Githubinfo(Base):
    __table__ = Table('githubinfo', metadata, autoload=True)


class Visiturl(Base):
    __table__ = Table('visiturl', metadata, autoload=True)


class SqlOpt():
    def __init__(self):
        self.session = Session()

    def insert_visit(self, hashvalue, url):
        try:
            visitobj = Visiturl(hashvalue=hashvalue, url=url)
            self.session.add(visitobj)
            self.session.commit()
            return True
        except Exception as e:
            return False

    def insert_info(self, hashvalue, url, email, time, checked=0):
        try:
            infoobj = Githubinfo(hashvalue=hashvalue,
                url=url, email=email, time=time, checked=checked)
            self.session.add(infoobj)
            self.session.commit()
            return True
        except Exception as e:
            return False


    def query_visit(self, hashvalue):
        v_url = self.session.query(Visiturl).filter_by(hashvalue=hashvalue).all()
        if v_url:
            return True
        else:
            return False
    def close(self):
        self.session.close()


if __name__ == '__main__':
    a = SqlOpt()
    # if a.query_visit("1234566"):
    #     print "Yes"
    # else:
    #     print "No"

    # if a.insert_visit("12345", "http://www.iqiyi.com"):
    #     print "insert success"
    # else:
    #     print "insert failed"
    b = SqlOpt()
    assert a.session == b.session
    a.close()
    b.close()


