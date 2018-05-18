#!/usr/bin/env python
# coding=utf-8

import hashlib
import time
import random
import re
import smtplib

from email.mime.text import MIMEText
from email.header import Header
from crawl_proxy import *


reg_emails1 = re.compile('[\w!#$%&\'*+/=?^_`{|}~-]+(?:\.[\w!#$%&\'*+/=?^_`{|}~-]+)*'+'@(?:[\w](?:[\w-]*[\w])?\.)'+'[\w](?:[\w-]*[\w])?')
reg_emails2 = re.compile('[\w!#$%&\'*+/=?^_`{|}~-]+(?:\.[\w!#$%&\'*+/=?^_`{|}~-]+)*'+'@(?:[\w](?:[\w-]*[\w])?\.)'+'(?:[\w](?:[\w-]*[\w])?\.)'+'[\w](?:[\w-]*[\w])?')

proxy_list = []

headers={
    'User-Agent' : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0',
    "Accept-Language" : "zh-CN,zh;q=0.8,zh-TW;q=0.3",
    "Accept" : "text/html,",
    "Connection" : "close",
    "Cookie" : "_octo=GH1.1.1985934553.1505834380; logged_in=yes; dotcom_user=viewer2015; user_session=gETz7G7tqReB__HSWOZeFrZwzHo3rego-gM2DArFZX16w3jW; __Host-user_session_same_site=gETz7G7tqReB__HSWOZeFrZwzHo3rego-gM2DArFZX16w3jW; _gh_sess=eyJsYXN0X3dyaXRlIjoxNTA1OTA4NDc2NzQ5LCJzZXNzaW9uX2lkIjoiNjkwNWU1Y2E5NjE2Yjg4ZmRhNjkzYzljNjhjYTIyOTAiLCJsYXN0X3JlYWRfZnJvbV9yZXBsaWNhcyI6MTUwNTk4MjkyMjk4Niwic3B5X3JlcG8iOiJyaW5nMDRoL3BhcGVycyIsInNweV9yZXBvX2F0IjoxNTA1OTIxNzU3LCJjb250ZXh0IjoiLyIsImZsYXNoIjp7ImRpc2NhcmQiOlsiYW5hbHl0aWNzX2xvY2F0aW9uIl0sImZsYXNoZXMiOnsiYW5hbHl0aWNzX2xvY2F0aW9uIjoiL2Rhc2hib2FyZCJ9fX0%3D--afa300ef4905c21803df2afd9e331aa0b19c324c; _ga=GA1.2.1722114177.1505834380; _gat=1; tz=Asia%2FShanghai",
    "Referer" : "https://github.com/",
    "Upgrade-Insecure-Requests" : "1",
    "x-requested-with" : "XMLHttpRequest",
    "Content-Type" : "application/x-www-form-urlencoded; charset=UTF-8",
    "X-PJAX" : "true",
    "X-PJAX-Container" : "#js-pjax-container",
    }

raw_headers = {
    "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0",
    "Accept" : "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language" : "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
    "Accept-Encoding" : "gzip, deflate, br",
    "DNT" : "1",
    "Connection" : "close",
    "Upgrade-Insecure-Requests" : "1",
}


user_agents = [
    # 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/9.0.3 Safari/7046A194A',
    'Opera/9.80 (X11; Linux i686; Ubuntu/14.10) Presto/2.12.388 Version/12.16',
    'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/50.1',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.19 (KHTML, like Gecko) Ubuntu/11.10 Chromium/18.0.1025.142 Chrome/18.0.1025.142 Safari/535.19',
]

domains=["tencent.com","baidu.com","sohu.com","alibaba.com","alibaba-inc.com","360.cn","renren.com","ifeng.com","sogou-inc.com","9you.com","duba.net","xunlei.com","ctrip.com","19lou.com","douban.com","youku.com","wanmei.com","uc.cn","pps.tv","taobao.com","alipay.com","lenovo.com","17173.com","qiyi.com","tudou.com","51.com","4399.com","huawei.com","ku6.com","xiami.com","qunar.com","7daysinn.cn","58.com","ganji.com","duowan.com","pindao.com","jd.com","91wan.com","guokr.com","zhihu.com","pptv.com","9158.com","hudong.com","bianfeng.com","6.cn","elong.com","taomee.com","yxlink.com","zhenai.com","dangdang.com","aipai.com","xiaomi.com","joy.cn","letao.com","jingwei.com","51job.com","sf-express.com","kingsoft.com","leyou.com","jiayuan.com","soufun.com","youtx.com","lefeng.com","yoybuy.com","eset.com.cn","7k7k.com","aqgj.cn","guosen.com.cn","ly.com","veryeast.cn","12306.cn","goodbaby.com","cenwor.com","tttuangou.net","yonyou.com","vip.com","ftsafe.com.cn","csdn.net","topsec.com.cn","wanda.cn","letv.com","diandian.com","kugou.com","us.syyx.com","xiu.com","baihe.com","kingdee.com","iboxpay.com","playcool.com","duote.com","wdlinux.cn","yupoo.com","263.net","coo8.com","wooyun.org","36kr.com","tianya.cn","suning.com","zol.com.cn","easybuy.com.cn","jiajia.me","5173.com","baobeihuijia.com","neusoft.com","gamemayi.com","51web.com","dajie.com","qianpin.com","2345.com","51cto.com","lvmama.com","happigo.com","m18.com","gooann.com","lakala.com","knownsec.com","99.com","xd.com","jiapin.com","docin.com","ip66.com","tnyoo.com","cwan.com","dianping.com","sclub.com.tw","iciba.com","xoyo.com","ijinshan.com","xueqiu.com","chinacache.com","hx168.com.cn","17sup.com","mangocity.com","shop.edu.cn","tiexue.net","cpic.com.cn","venustech.com.cn","huatu.com","178.com","yihaodian.com","house365.com","51greenorange.com","360shop.com.cn","weibo.com","touzhu.cn","qiaogu.com","zblogcn.com","xcar.com.cn","goldmail.cn","trip8080.com","baijob.com","zhubajie.com","acfun.tv","qfpay.com","xianguo.com","tp-link.com.cn","zhenpin.com","hiall.com.cn","800app.com","yuantiku.com","redbaby.com.cn","baixing.com","2cto.com","linktrust.com.cn","womai.com","tuciabbay.com","1ting.com","akcms.com","kingosoft.com","meitu.com","meizu.com","taocms.org","53kf.com","oschina.net","thinksns.com","hxage.com","moliyo.com","3158.cn","oppo.com","tuniu.com","3158.com","meituan.com","eversec.com.cn","kuaibo.com","cins.cn","papa.me","591wed.com","cheshi.com","shopxx.net","m1905.com","argos.cn","tgbus.com","mafengwo.cn","cnblogs.comcmt","fun.tv","hupu.com","sudu.cn","feng.com","nandu.com","changba.com","jinwankansha.com","51bi.com","chinaz.com","umeng.com","mogujie.com","xinghua.org.cn","coolping.com","chinanetcenter.com","iyiyun.com","yunyun.com","eguan.cn","winenice.com","opera.com","zhimei.com","tongbu.com","haodf.com","3322.org","dodonew.com","lesuke.com","iiyi.com","sudytech.com","8684.cn","bjsako.com","newsmyshop.com","tiancity.com","looyu.com","jollymm.com","dopool.com","fantong.com","zhuna.cn","secoo.com","gamtee.com","huanqiu.com","kanglu.com","wssys.net","xinnet.com","ebrun.com","duoshuo.com","bilibili.tv","gfan.com","pconline.com.cn","50cms.com","trs.com.cn","xdf.cn","htinns.com","wacai.com","mplife.com","donews.com","qyer.com","9978.cn","admin5.com","etuan.com","liepin.com","998.com","eastmoney.com","hc360.com","welove520.com","autonavi.com","lusen.com","ecisp.cn","lightinthebox.com","desdev.cn","sgcc.com.cn","mydrivers.com","zte.com.cn","56.com","mbaobao.com","airchina.com.cn","spacebuilder.cn","eyou.net","jstv.com","yesky.com","anjuke.com","hexun.com","creditcard.cmbc.com.cn","founderbn.com","youmi.cn","ceair.com","sdcms.cn","gddddo.cn","now.cn","safedog.cn","hiwifi.com","jeecms.com","gewara.com","rong360.com","renrendai.com","zzidc.com","jiuxian.com","yinyuetai.com","tcl.com","sootoo.com","ppdai.com","locojoy.com","5sing.com","candou.com","appchina.com","300.cn","phpstat.net","52pk.com","shendu.com","ccidnet.com","diditaxi.com.cn","jiankongbao.com","fc.tcl.com","aicai.com","smartisan.cn","sto.cn","duokan.com","cndns.com","haier.net","haier.com","ehaier.com","jushanghui.com","hairongyi.com","ooopic.com","autohome.com.cn","che168.com","pp.cc","super8.com.cn","17k.com","59.cn","zhaopin.com","amazon.cn","yundaex.com","51zhangdan.com","leiphone.com","ikuai8.com","aoshitang.com","codoon.com","moko.cc","nuomi.com","liba.com","tuan800.com","bizcn.com","destoon.com","22.cn","baofeng.com","kyfw.12306.cn","zgsj.com","chuangxin.com","diyou.cn","zbird.com","e-chinalife.com","kuaiyong.com","v5shop.com.cn","zuzuche.com","chinapost.com.cn","pook.com","4.cn","crsky.com","wandoujia.com","oupeng.com","h3c.com","pcauto.com.cn","pclady.com.cn","pcbaby.com.cn","pcgames.com.cn","pchouse.com.cn","baomihua.com","dolphin.com","pcpop.com","itpub.net","zhe800.com","caijing.com.cn","hikvision.com","bitauto.com","fengyunzhibo.com","app111.com","hanweb.com","id5.cn","jumei.com","onefoundation.cn","weipai.cn","zuche.com","sfbest.com","dbappsecurity.com.cn","jobui.com","imobile.com.cn","shenzhenair.com","douguo.com","v1.cn","diyicai.com","kuwo.cn","csair.com","mama.cn","115.com","foxitsoftware.cn","zto.cn","cofco.com","mycolorway.com","breadtrip.com","qiniu.com","mingdao.com","zoomla.cn","ename.cn","feixin.10086.cn","icafe8.com","anymacro.com","zhujiwu.com","ele.me","phpyun.com","thinkphp.cn","500wan.com","paidai.com","fumu.com","homeinns.com","chinabank.com.cn","meishichina.com","hinews.cn","jj.cn","immomo.com","cnaaa.com","duobei.com","gw.com.cn","tieyou.com","qibosoft.com","zqgame.com","meilishuo.com","sitestar.cn","qmango.com","sohu-inc.com","onlylady.com","edong.com","99bill.com","12321.cn","kongzhong.com","ucloud.cn","kuaidadi.com","cyzone.cn","ujipin.com","damai.cn","jinjianginns.com","stockstar.com","zdnet.com.cn","netentsec.com","spb.gov.cn","cnzxsoft.com","chinaamc.com","china.com","jb51.net","cmstop.com","lecai.com","yongche.com","pingan.com","51credit.com","cnfol.com","china-sss.com","btcchina.com","okcoin.com","kaspersky.com.cn","yinxiang.com","nipic.com","antiy.com","juhe.cn","wumii.org","uzai.com","anzhi.com","yto.net.cn","58pic.com","t3.com.cn","aibang.com","yaolan.com","zhongchou.com","ubuntu.org.cn","smartisan.com","hb-n-tax.gov.cn","chanjet.com","bytedance.com","1hai.cn","tebon.com.cn","tdxinfo.com","tujia.com","cmbchina.com","dbw.cn","pingan.com","legendsec.com","woniu.com","mcafee.com","vasee.com","juesheng.com","wasu.cn","wowsai.com","chinadaily.com.cn","51talk.com","mbachina.com","ifanr.com","boc.cn","gongchang.com","nbcb.com.cn","91160.com","imooc.com","gf.com.cn","bangcle.com","zhuqu.com","cnmo.com","17ugo.com","zcool.com.cn","jiemian.com","creditease.cn","7po.com","itenable.com.cn","tesla.cn","szse.cn","enorth.com.cn","newone.com.cn","haodai.com","cdb.com.cn","sino-life.com","coocaa.com","cgbchina.com.cn","17500.cn","chsi.com.cn","yz.chsi.com.cn","cnpc.com.cn","petrochina.com.cn","welomo.com","zank.mobi","kf5.com","ehaier.com","piccnet.com.cn","88.com.cn","shenhuagroup.com.cn","unionpayintl.com","haigou.unionpay.com","youzu.com","yxdown.com","56.com","gopay.com.cn","wiwide.com","fesco.com.cn","samsung.com","sfn.cn","chinaums.com","htsc.com.cn","ciwong.com","hp.com","itouzi.com","cs.ecitic.com","to8to.com","camera360.com","cfsc.com.cn","ebscn.com","24cp.com","chinahr.com","sinopec.com","mcdonalds.com.cn","chexun.com","jinri.cn","psbc.com","swsresearch.com","picchealth.com","cnooc.com.cn","yohobuy.com","h3c.com","icbccs.com.cn","umetrip.com","sunits.com","youyuan.com","cdrcb.com","comba.com.cn","adtsec.com","nffund.com","zhaoshang.net","cytobacco.com","weizhonggou.com","addnewer.com","scti.cn","feiniu.com","chinapnr.com","heetian.com","yungouos.com","zjedu.org","ccic-net.com.cn","shengpay.com","yirendai.com","essence.com.cn","1218.com.cn","228.com.cn","anbanggroup.com","m6go.com","xiangshe.com","vvipone.com","51jingying.com","cmbc.com.cn","51idc.com","autono1.com","jsbchina.cn","dfzq.com.cn","ssscc.com.cn","chaoxing.com","yingjiesheng.com","thfund.com.cn","duxiu.com","myfund.com","x.com.cn","cits.cn","lufax.com","hongkongairlines.com","touna.cn","hhedai.com","jinlianchu.com","tsinghua.edu.cn","qufenqi.com","tv.tcl.com","pinganfang.com","boqii.com","plu.cn","flnet.com","beibei.com","mizhe.com","vivo.com.cn","ahtv.cn","daling.com","cankaoxiaoxi.com","s.cn","lingying.com","voc.com.cn","bankofshanghai.com","wukonglicai.com","zszq.com","fanhuan.com","zhiwang.yixin.com","91jinrong.com","cec.com.cn","jxlife.com.cn","csrc.gov.cn","dianrong.com","leyou.com.cn","benlai.com","cdce.cn","fxiaoke.com","metao.com","minmetals.com.cn","jzjt.com","sinosig.com","umpay.com","sgcc.com.cn","leju.com","fuzegame.tv","fuzegame.com","lonlife.cn","zbj.com","didichuxing.com","emao.com","cang.com","qianxs.com","meican.com","westsecu.com","feidee.com","easou.com","easou-inc.com","csvw.com","cjn.cn","pku.edu.cn","longzhu.com","jdpay.com","tuhu.cn","yahui.cc", "zufangit.cn", "gionee.com"]

def get_md5(url):
    return hashlib.md5(url).hexdigest()


def getTime():
    return time.strftime("%Y-%m-%d", time.localtime())

def get_randomUA():
    return user_agents[random.randint(0, len(user_agents) - 1)]

def getHtmlurl(html):
    reg = r'href="(.*?)" title'
    urlre = re.compile(reg)
    urllist = re.findall(urlre, html)
    return urllist

def load_proxy(sure=True):
    if sure:
        global proxy_list
        with open("valid_proxy.txt", "r") as f:
            for i in f:
                if i.startswith("http"):
                    i = i.strip()
                    protocal, proxy = i.split("://")[0], i.split("://")[1]
                    proxy_list.append((protocal, proxy))
        proxy_list = list(set(proxy_list))
    else:
        pass


def random_proxy():
    if proxy_list:
        return proxy_list[random.randint(0, len(proxy_list) - 1)]
    else:
        return ""


def write_file(filename, info):
    with open(filename, "a") as f:
        f.write(info + "\n")


def send_mail(url, email):
    # 第三方 SMTP 服务
    mail_host="smtp.163.com"  #设置服务器
    mail_user="xiaoyan_jia1"    #用户名
    mail_pass="mdf25114"   #口令

    print mail_pass
    sender = 'xiaoyan_jia1@163.com'
    receivers = ['xiaoyan_jia1@163.com']  # 接收邮件，可设置为你的QQ邮箱或者其他邮箱

    mail_msg = """
    The info URL: <a href="{}">{}</a><br/>
    The email is: <b>{}</b>
    <script>
    alert(1);
    </script>
    """.format(url, url, email)

    message = MIMEText(mail_msg, 'html', 'utf-8')
    message['From'] = Header("扫描测试", 'utf-8')
    message['To'] =  Header("github", 'utf-8')

    subject = 'github info scan'
    message['Subject'] = Header(subject, 'utf-8')


    try:
        smtpObj = smtplib.SMTP()
        smtpObj.connect(mail_host, 25)    # 25 为 SMTP 端口号
        smtpObj.login(mail_user,mail_pass)
        smtpObj.sendmail(sender, receivers, message.as_string())
        print "send done"
    except Exception as e:
        print "Error: " + repr(e)

if __name__ == '__main__':
    send_mail("httpw://www.iqiyi.com", "test@iqiyi.com")
