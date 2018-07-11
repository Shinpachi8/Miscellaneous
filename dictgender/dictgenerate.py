#!/usr/bin/env python
# coding=utf-8

'''
python 字典生成器, 输入为常见的500用户名，
用户输入: 公司名称
'''

import datetime
import argparse
import sys


def parse_arg():
    parser = argparse.ArgumentParser(description='Process some integers.')

    date_parser = parser.add_mutually_exclusive_group(required=False)
    date_parser.add_argument('--date', dest='date', action='store_true', help='if wanna add birth date, like wangwei@0707, default True')
    date_parser.add_argument('--no-date', dest='date', action='store_false', help='if don not wanna birth date')
    parser.set_defaults(date=True)
    # parser.add_argument_group(date_parser)

    nametrans_parser = parser.add_mutually_exclusive_group(required=False)
    nametrans_parser.add_argument('--nametrans', dest='nametrans', action='store_true', help='if wanna change username like, from wangwei to WANGWEI, Wangwei')
    nametrans_parser.add_argument('--no-nametrans', dest='nametrans', action='store_false')
    parser.set_defaults(nametrans=False)
    # parser.add_argument_group(name_parser)

    parser.add_argument('--file', help='the file contains useranme eachline')
    parser.add_argument('--company', help='the company name want generate, if iqiyi.com, only use iqiyi, do not input subdomain')
    parser.add_argument('--name', default='wangwei', help='the username wanna generate, default: wangwei')
    parser.add_argument('--csv',  help='generate the csv file, seperate is `:`, default output name is time.csv')

    args = parser.parse_args()
    return args



class GeneratePassword(object):
    '''
    一个生成密码的字典，根据猪猪侠的paper， 
    https://github.com/ring04h/papers/blob/master/%E8%87%AA%E5%8A%A8%E5%8C%96%E6%94%BB%E5%87%BB%E8%83%8C%E6%99%AF%E4%B8%8B%E7%9A%84%E8%BF%87%E5%8E%BB%E3%80%81%E7%8E%B0%E5%9C%A8%E4%B8%8E%E6%9C%AA%E6%9D%A5--20140910.pdf

    '''
    default_weak_password = '123456,admin,123456789,12345678,111111,000000,11111111,00000000,123123123,1234567890,88888888,111111111,147258369,987654321,aaaaaaaa,1111111111,xiazhili,66666666,11223344,a123456789,1qaz2wsx,789456123,qqqqqqqq,87654321,password,000000000,qwertyuiop,31415926,iloveyou,qq123456,0000000000,12344321,asdfghjkl,1q2w3e4r,12121212,0123456789,123654789,qazwsxedc,abcd1234,12341234,123456abc,110110110,abc123456,22222222,1234qwer,a12345678,123321123,asdasdasd,123456123,qwertyui,a1234567,123456789a,99999999,999999999,asdfasdf,123456aa,123456123456,aa123456,963852741,55555555,520520520,741852963,33333333,qwer1234,asd123456,77777777,05962514787,11112222,kingcom5,111222333,zzzzzzzz,3.1415926,qweasdzxc,qweqweqwe,123456qq,1123581321,asdf1234,123698745,521521521,147852369,asdfghjk,code8925,q1w2e3r4,12345678a,1234abcd,woaiwojia,woaini1314,123qweasd,1qazxsw2,0987654321,321321321,5845201314,lilylily,wwwwwwww,123456987,11235813,zxcvbnm123,1q2w3e4r5t,google250,123321aa,123456asd,10101010,12345600,1234554321,12345612,woshishui,11111111111111111111,xiaoxiao,5201314520,qwe123456,wojiushiwo,123456654321,12369874,12301230,1234567b,12345679,ffffffff,1122334455,woaini123,100200300,44444444,ssssssss,qazwsx123,1234567a,buzhidao,z123456789,1357924680,woainima,123456aaa,25257758,yangyang,321654987,csdncsdn,woaini520,aaa123456,369258147,5845211314,299792458,9876543210,369369369,q123456789,20082008,zhang123,dddddddd,qwerasdf,12qwaszx,12345678910,8888888888,aaaaaaaaa,888888888,wiii2dsE,135792468,goodluck,wocaonima,a1111111,168168168,abcdefgh,789789789,66668888,1233211234567,qaz123456,computer,007007007,123456qwe,112233445566,abc12345,zxc123456,qq123123,147896325,zxczxczxc,newhappy,a1b2c3d4,qq111111,sunshine,00001111,xxxxxxxx,52013145201314,zaq12wsx,123321123321,lb851210,qqq11111,helloworld,wodemima,as123456,1a2b3c4d,123789456,superman,110120119,zhangwei,584131421,123456789.,20092009,12345qwert,aptx4869,aaaaaaaaaa,13145200,77585210,aaaa1111,123456ab,666666666,12348765,tiantian,123456..,12312312,jingjing,123456789q,li123456,20080808,tzwadmin123,1234512345,abcd123456,hyjzstx8,a123123123,wangjian,a5201314,13141314,a123456a,20102010,qw123456,23232323,w123456789,12345687,456456456,01020304,shanghai,7894561230,01234567,12345abcde,QWERTYUIOP,19491001,14789632,123123123123,3141592653,ab123456,AAAAAAAA,5841314520,01010101,77585211,p@ssw0rd,111111,a11111111,012345678,dongdong,justdoit,yuanyuan,csdn.net,123454321,P@ssw0rd,qazqazqaz,7758521521,123456as,q1w2e3r4t5,hahahaha,45612300,woaini521,aa123123,77585217758521,wang123456,23456789,13131313,110119120,zhanglei,88889999,74108520,123qwe123,123456zx,worinima,aaa123123,77889900,123456000,518518518,111111aa,584131420,12365478,1111qqqq,wangjing,11111111a,qwert12345,meiyoumima,11110000,q1234567,258258258,qq000000,mingming,liu123456,987456321,52013141314,123456798,1234567890123,qazxswedc,zz123456,chenchen,25251325,qqqqqqqqqq,aini1314,333333333,911911911,21212121,123456abcd,llllllll,10203040,560111aa,52013140,q1111111,1234asdf,zx123456,woailaopo,1237890o0,123123aa,abc123456789,qq123456789,q12345678,ASDFGHJKL,asasasas,78787878,5201314a,nicholas,admin123,55667788,120120120,1234567899,wangwang,qq5201314,1qaz1qaz,12332100,123123456,dg123456,16897168,xiaolong,passw0rd,mmmmmmmm,jjjjjjjj,a1s2d3f4,99998888,66778899,00000000000000000000,support123,wangpeng,administrator,a0000000,1QAZ2WSX,zxcv1234,zaiwa1124,w12345678,longlong,pppppppp,kkkkkkkk,xingxing,1223334444,wangyang,abcde12345,a00000000,13572468,123456qaz,lovelove,12131415,qweasd123,love1314,asdf123456,qwerty123,12300000,1111aaaa,qqqqqqqqq,hhhhhhhh,1314520520,nihao123,miaomiao,3141592654,00123456,qwe123123,liangliang,Aa123456,xiaoqiang,qwe12345,hello123,cccccccc,asdfjkl;,zhanghao,121121121,112112112,www123456,testtest,A123456789,3366994qaz,200401265,1111111a,zhimakaimen,zhangjie,asd12345,56565656,456789123,456123789,119119119,111111qq,yyyyyyyy,QAZWSXEDC,q11111111,abc12345678,84131421,6666666666,222222222,oooooooo,xiaofeng,woshitiancai,qwqwqwqw,imissyou,gggggggg,baidu1599,00112233,internet,13324016206,zhangjian,mm123456,98989898,83869247,1qaz2wsx3edc,123456qw,shanshan,jack123456,123456ok,100100100,wobuzhidao,98765432,5555555555,314159265,123456789abc,1212121212,zhongguo,zhangjing,woainiwoaini,microsoft,123581321,11221122,789654123,5201314123,12345689,123456780,qqqq1111,159159159,1029384756,tingting,dingding,147147147,123456789123,001001001,z1234567,wangchao,tsinghua,huanhuan,5841314521,11111111111,89898989,123456bb,zaq1xsw2,555555555,123abc123,123456456,369852147,amuqdedwft,963258741,1q1q1q1q,12312300,rongfan66,58585858,31496081,110120130,z12345678,windowsxp,china6815,1231512315,cs123456,88886666,14141414,13145201314520,woshishei,jianqiao,123654123,chinaren,1qaz@WSX,12345611,520131400,12345678q,handsome,789632145,123456zz,12332112,qwerqwer,l12345678,a1314520,68686868,w1234567,123123qq,chenjian,asdfzxcv,159357159357,09090909,584201314,123456...,wangyong,wang1234,lingling,cc123456,10002000,09876543,zhangyan,qwertyuio,777888999,100200100200,beijing2008,7758521520,16899168,123456321,27105821,159753123,123456789z,haohaoxuexi,123456asdf,05413330,zhanghui,huang123,20052005,zhangyang,wo123456,301415926,21876346a,159357123,123698741,123456qwerty,rilidongl,13141516,zxcvbnm1,msconfig,jiangnan,abcabcabc,18181818,0.123456,wangying,tttttttt,qawsedrf,kingking,admin888,55556666,123qweasdzxc,12345abc,1111111q,zxcvbnma,woaiwoziji,operation,nclpf2p4,asd123123,zhangjun,ABC123456,90909090,78963214,123456789qaz,zhangtao,woshishen,134679852,wiiisa222,l123456789,chen123456,99887766,777777777,2222222222,11111112,QQQQQQQQ,nishishui,Fuyume123,12345677,12345671,niaishui,123456zxc,123456788,00000001,........,ww123456,dgdg7234322,13149286ab,123654987,QWERTYUI,qingqing,333666999,zxcvbnmzxcvbnm,yy123456,woaimama,qwe123qwe,1234567q,123321456,00009999,yingying,xiaoming,51201314,123456ABC,123456789@,12345654321,10000000,windows123,wangliang,9999999999,9638527410,125125125,001002003,zhangpeng,nishizhu,huangjie,goo78leeg,asdfgh123,741258963,55665566,31415926535,zhangzhang,woshizhu,wanggang,poiuytrewq,liuqiang,ABCD1234,a7758521,7708801314520,192837465,159357456,12345678900,QQ123456,asdffdsa,aa111111,zxzxzxzx,bbbbbbbb,65432100,123456789qq,zhangqiang,111111111111,wangdong,hao123456,fangfang,85208520,12356789,qweqwe123,howareyou,bugaosuni,abcdefg123,abc123abc,700629gh,21345678,1qa2ws3ed,wangzhen,ss123456,f19841205,asdfqwer,7215217758991,25252525,1415926535,123456789+,01230123,zxcvbnmm,wangfeng,songaideng,mengmeng,download,qianqian,159753159753,1234567891,zhangkai,yu123456,jiaojiao,huangwei,74107410,10241024,000123456,00000000a,zhangxin,zhangbin,zaqxswcde,xj123456,wangning,test1234,stefanie,jianjian,fengfeng,7758521a,20090909,12332111,x123456789,supervisor,qwert123,cyq721225,95279527,52113145211314,52001314,3.141592653,20202020,12345666,zxcasdqwe,bingbing,asdqwe123,asdasd123,zxcvzxcv,s2j3l9v5,qazwsxed,dangyuan,abc123123,584211314,12345670,000000,zhangliang,qaz12345,pengpeng,lkjhgfdsa,ILOVEYOU,cndkervip,1a2s3d4f,13145210,xiaodong,wangmeng,987987987,5205201314,315315315,20022002,1Q2W3E4R,12346789,12345688,yangguang,xx123456,wangqiang,jiushiaini,huanghao,csdn123456,asdfg12345,1q2w3e4r5t6y,1357913579,123456789*,1213141516,zhouzhou,woshiniba,s123456789,qqqqwwww,adminadmin,201314201314,by7704566,aabbccdd,aaaa1234,88488848,77585211314,60200946,52013141,12345789,123456789A,zzzzzzzzz,zhendeaini,yangjing,yangchao,yang123456,xiaojing,sun123456,s12345678,s1234567,qqq123456,hao456250,caonima123,77778888,123456qqq,zhang123456,yang1234,wangming,mimamima,happy123,abcd12345,aaaa0000,9876543211,987412365,60729043,521224727,334205265,15151515,000000aa,yaho982er,xuanxuan,weiweiwei,jb85811510,feixiang,asdfg123,86868686,25802580,1010101010,whoareyou,thankyou,slamdunk,jiangwei,gogogogo,caonimabi,987654123,891023hh,541881452,456852456852,36363636,20062006,175638080,16888888,woshinidie,rongrong,pingping,liujianliu,football,asd123asd,37213721,33445566,0.123456789,tangtang,chen1234,amp12345,abc123abc123,53231323,5201314.,20000000,16161616,13800138000,11111122,yangjian,xiaogang,wonderful,wangchen,qwerty123456,ms0123456,ll123456,hhxxttxs,fdsafdsa,7777777777,52013145,1234QWER,123456789123456789,123456654,09308066,0147258369,yongheng,xiaojian,workhard,kangkang,963963963,22334455,123456ww,11211121,wanghuan,qq1314520,laopo521,hellohello,csdn1234,chenfeng,chenchao,butterfly,a1b2c3d4e5,A1234567,5211314521,04020323,zzzzzzzzzz,shoujiqb,l1234567,apple123,44556677,38183818,20082009,131452000,123123qwe,123123321,zhangchao,wangshuai,thinkpad,songsong,paradise,iloveyou1314,80808080,52105210,147896321,123123123a,1111122222,zaqwsx123,xiaoyang,tongtong,okokokok,chenliang,beautiful,aaaassss,7758521123,775852100,69696969,5201314qq,101101101,zhangming,xixihaha,xiangxiang,woaini11,sdfsdfsdf,samleiming,qazwsx12,jiarenqb,foreverlove,adgjmptw,A12345678,520090025hgb,0054444944,0000000a,zhangying,woainiya,westlife,PASSWORD,Passw0rd,lin123456,jiang123,dirdirdir,cnforyou,chenjing,ASDASDASD,22223333,1a2b3c4d5e,159753456,123456789w,12342234,0.0.0.0.,wokaonima,tomorrow,q1q1q1q1,kk123456,fighting,96321478,3333333333,159357258,1472583690,123456789asd,tiankong,qingfeng,caonimama,22446688,!QAZ2wsx,xinxin13d,qq123321,jianghui,delphi2009,bbscsdnnet,bai18dudu,APTX4869,a89400ab,96385274,520fagnsg,51515151,20042004,19191919,123456xx,112233112233,zhangfeng,lilingjie1102,huangjian,a1a1a1a1,77582588,654321654321,630158513,546546546,54181452,52013144,15975300,123456AA,123456789987654321,11223300,zy123456,zhanghua,xiaoliang,wu123456,woxiangni,windows98,software,lxqqqqqq,jordan23,ingtake1,chenyang,AA123456,99990000,891129aaa,70701111,551648586,12345678.,zhenzhen,xiaofang,showmethe,qq1234567,ly123456,kobebryant,jiangtao,huanjue321,goodgood,accpaccp,80238023,77887788,45454545,1314520123,110112119,11001100,0147896325,zoo-1573,yongyuan,xu123456,wangxiao,shevchenko,lj123456,liang123,juventus,123qwe!@#,qwe123!@#,1qaz@WSX,ZAQ!xsw2,ZAQ!2wsx,2wsx#EDC,@WSX3edc,#EDC2wsx,3edc$RFV,#EDC4rfv,$RFV3edc,4rfv#EDC,%TGB6yhn,5tgb^YHN,^YHN5tgb,6yhn%TGB,6yhn&UJM,^YHN7ujm,&UJM6yhn,7ujm^YHN,8ik,(OL>,*IK<9ol.,2wsx!QAZ,!QAZ2wsx,!QAZ2wsx,zaq!2WSX,!qazXSW2,@wsxZAQ1,qwer1234*,1q2w3e4r5t!@#,1qaz2wsx,hao123,Qwertyu8'
    def __init__(self, name='', filename='', company='', csv='', date=True, name_trans=False):
        self.name = name
        self.filename =filename
        self.company = company
        self.date = date
        self.name_trans = name_trans
        self.csv = csv
        

    def gen_time(self):
        '''
        生成以0323为格式的日期
        :rtype: []
        '''
        timelist = []
        for month in xrange(1, 13):
            for day in xrange(1, 32):
                item = '{:02}{:02}'.format(month, day)
                timelist.append(item)
        return timelist


    def gen_company(self, company):
        '''
        生成公司的变种
        :param: company，  公司名,如iqiyi.com 输入iqiyi
        :rtype: list
        '''
        companylist = []
        # 全大写
        upper_company = company.upper()
        # 全小写
        lower_company = company.lower()
        # 首字符大写
        cap_company = company.capitalize()

        # 第一个字符变换
        trans = {'i':'1',
                'a':'4',
                'e':'3',
                'o':'0',
                'q':'9',
                'z':'2'}
        for key in trans:
            companylist.append(company.replace(key, trans[key], 1))
            companylist.append(company.replace(key, trans[key], 2))
            companylist.append(company.replace(key, trans[key]))
        
        companylist.append(upper_company)
        companylist.append(lower_company)
        companylist.append(cap_company)

        companylist = list(set(companylist))
        return companylist
        

    def gen_name(self, name, company):
        namelist = []
        split_char = ['', '@', '#', '.', '!', '&', '$']
        expand_char = ['', '!', '!!', '!!!', '!@#', '!@#$', '!QAZ', '#', '##', '###']
        expand_char += ['$', '$$', '%', '%%', '&', '&&', '*', '**', '***']
        expand_char += ['...', '000', '000.', '1', '1.', '110', '110.', '111']
        expand_char += ['111.', '1122', '1122.', '119', '119.', '12', '12.', '123']
        expand_char += ['222', '123.', 'com', '123123', '1234', '12345', '1234.', '123456']
        expand_char += ['1314', '1314.', '1qaz', '222.', '321', '666', '777', '321.', '333']
        expand_char += ['444', '444.', '520', '520.', '5201314', '521', '521.', '555', '666.']
        expand_char += ['ab', 'Ab', 'Abc', 'QWE', 'qwer', 'abc', '888', '8888.', '888.','@']
        expand_char += ['@@', '@@@', 'ASDF', 'ASD', 'asd', 'Aa', 'x', 'xx', 'xxx', 'zxc', 'zxcv']
        expand_char += ['ZXC', 'a', 'aa', 'aaa', 'abcd', 'cc', 'qaz', 'sb']
    

        companylist = self.gen_company(company)
        datelist = self.gen_time()
        if self.name_trans:
            translateNameList = [name, name.capitalize(), name.upper()]
        else:
            translateNameList = [name,]
        # 生成 name,split_char,company
        for name in translateNameList:
            for char in split_char:
                for company in companylist:
                    namelist.append('{}{}{}'.format(name, char,company))
        
        # 生成name, split_char, expand_char
        for name in translateNameList:
            for char in split_char:
                for ex in expand_char:
                    namelist.append('{}{}{}'.format(name,char,ex))
        
        #生成company,split_char,expand_char
        for company in companylist:
            for char in split_char:
                for ex in expand_char:
                    namelist.append("{}{}{}".format(company,char,ex))
        
        if self.date:
            # 生成name, split_char, data:
            for name in translateNameList:
                for char in split_char:
                    for date in datelist:
                        namelist.append('{}{}{}'.format(name,char,date))

        namelist = list(set(namelist))
        namelist.extend(GeneratePassword.default_weak_password.split(","))

        return namelist


    def generate(self):
        if self.csv:
            output = self.csv
        else:
            time = datetime.datetime.now()
            output = time.strftime('%Y-%m-%d-%H')
            output = output + '.csv'
        
        if not self.filename and not self.name:
            with open(output, 'w') as f:
                # f.write('host:username:password\n')
                password = GeneratePassword.default_weak_password.split(',')
                for ps in password:
                    f.write('{}:{}:{}\n'.format(self.company,'wangwei',ps))
            return
        # 处理文件名
        names = []
        if self.filename:
            with open(self.filename, 'r') as f:
                for line in f:
                    name = line.strip()
                    names.append(name)
        if self.name:
            names.append(self.name)
        
        names = list(set(names))
        # 处理company
        company = self.company.split('.')[0]

        try:
            f = open(output, 'w')
            # f.write('host:username:password\n')
            for name in names:
                if name:
                    password = self.gen_name(name, company)
                    print 'For name={} generate {} passwords'.format(name, len(password))
                    for ps in password:
                        f.write('{}:{}:{}\n'.format(self.company,name,ps))
            
        except Exception as e:
            print repr(e)
            f.close()



def main():
    args = parse_arg()
    name = args.name
    filename = args.file 
    company = args.company
    date = args.date 
    csv = args.csv
    name_trans = args.nametrans
    if not company:
        print 'company must add'
        args.print_help()
        sys.exit(-1)
    
    print name
    print filename
    print company
    print date
    print csv 
    print name_trans

    s = GeneratePassword(name=name, filename=filename, company=company, csv=csv)
    s.generate()

    


if __name__ == '__main__':
    main()