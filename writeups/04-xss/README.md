# XSS（跨站脚本）— DVWA

> 靶场：`vulnerables/web-dvwa`（DVWA v1.10 *Development*）
> 难度：Low ✅ ／ Medium ⬜ ／ High ⬜
> 日期：2026-09-26
> 工具：Burp Suite Community v2026.8
> 覆盖：**反射型（xss_r）／ 存储型（xss_s）／ DOM 型（xss_d）**

---

## 📋 使用说明（写完这篇就可以删掉这一段）

**进度条 = 数空白标记。目标：0 个。**

```powershell
cd D:\Code\web-security-lab
(Select-String -Path writeups\04-xss\README.md -Pattern ('待'+'填') -AllMatches).Matches.Count
```

> 现在跑会得到 **105**。改完文件再跑，**变成 0 就算写完**。

**⚠️ 别从头顺着填。** 按下面这个顺序做，每一轮都能独立收尾：

| 轮次 | 章节 | 干什么 | 大约 |
|---|---|---|---|
| **A** | §1 → §3 → 附 | **先补证据链**：存 `raw/` 六份报文，把复现过程写下来 | 60 min |
| **B** | §2 → §4 → §6 → §7 | **再讲原理**：源码、上下文、根因、修复 | 70 min |
| **C** | §8 → §9 | **最后接上日志/工具**：可见性矩阵、检测规则 | 40 min |
| **D** | §5 | 【选做·加分】cookie 窃取链 | 40 min |

**三条纪律：**

1. **标着「提示：…」的括号里的话只是引导，不是答案** —— 写你自己的结论
2. **每一节的"结论／★"比表格重要** —— 表格填不动就先写结论
3. **不确定的地方写"我不确定 ＋ 我猜是"** —— 这比空着有价值，回头我帮你校

---

## 0. 一句话总结

<!-- 提示：这一关跟前三关比，最特殊的地方是 ——
     一个模块里塞了【三个】子类型，外在表现一模一样（都是弹窗），
     但【拼接发生在哪】完全不同。
     一句话把"三种类型的本质区别"写出来。
     提示词：谁（服务器 or 浏览器）把 payload 拼进了页面。 -->

（待填）

---

## 1. 环境

| 项 | 值 |
|---|---|
| 靶场镜像 | `vulnerables/web-dvwa` |
| 服务端 | Apache 2.4.25 (Debian) ／ PHP 7.0.30 ／ MySQL(MariaDB) |
| 工具 | Burp Suite Community v2026.8 |
| 客户端 | Chrome 151（Windows） |

**三个入口：**

| 类型 | 入口 | 提交方式 | payload |
|---|---|---|---|
| 反射型 | `http://127.0.0.1:8080/vulnerabilities/xss_r/?name=` | GET | `<script>alert(1)</script>` |
| 存储型 | `http://127.0.0.1:8080/vulnerabilities/xss_s/` | **POST** | `<script>alert(1)</script>` |
| DOM 型 | `http://127.0.0.1:8080/vulnerabilities/xss_d/?default=` | GET（**但服务器不读它**） | `'><script>alert(1)</script>` |

> ⚠️ **注意最后一行的括号** —— 那是 DOM 型的全部秘密。

---

## 2. 漏洞原理

### 2.1 先分清三个词

<!-- 提示：这三个词是本模块的地基。用你自己的话写，别抄定义。
     写完后自检：能不能拿"浏览器"和"服务器"两个视角讲清楚。 -->

| 词 | 我的解释 |
|---|---|
| 同源策略（SOP） | 浏览器层面控制不同源之间相应的内容能不能被这个页面的js读到 |
| XSS | 跨站之间的脚本，代码在访问页面的源内执行 |
| DOM | 浏览器把HTTP响应里的HTML解析之后，在内存里搭起来的节点树。JavaScript操作的不是文本是这棵树。 |

**为什么 XSS 能"绕过"同源策略：**

<!-- 提示：不是绕过，是"根本不在它的管辖范围内"。
     因为代码是在【哪个 origin 里】跑的？ -->

代码是在被访问的源执行然后返回本地网页

**同源的"源"由哪三样东西组成：**

<!-- 提示：协议 + ____ + ____。端口不同算不算同源？ -->

协议 + 主机 + 端口
端口也必须一致

---

### 2.2 服务端代码（Low）★ 三种都要贴

<!-- 粘贴地址（可直接在浏览器打开，它会渲染成高亮源码）：
     http://127.0.0.1:8080/vulnerabilities/view_source.php?id=xss_r&security=low
     http://127.0.0.1:8080/vulnerabilities/view_source.php?id=xss_s&security=low
     http://127.0.0.1:8080/vulnerabilities/view_source.php?id=xss_d&security=low
     注意：三种都选 low -->

#### （1）反射型 xss_r

```php
<?php

header ("X-XSS-Protection: 0");

// Is there any input?
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
    // Feedback for end user
    echo '<pre>Hello ' . $_GET[ 'name' ] . '</pre>';
}

?>
```

#### （2）存储型 xss_s

```php
<?php

if( isset( $_POST[ 'btnSign' ] ) ) {
    // Get input
    $message = trim( $_POST[ 'mtxMessage' ] );
    $name    = trim( $_POST[ 'txtName' ] );

    // Sanitize message input
    $message = stripslashes( $message );
    $message = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $message ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));

    // Sanitize name input
    $name = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $name ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));

    // Update database
    $query  = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

    //mysql_close();
}

?>
```

#### （3）DOM 型 xss_d

**★ 这一关要粘【两样】—— 因为漏洞根本不在 PHP 里。**

**① `view_source` 给你的 PHP（它是空的）：**

```php
<?php

# No protections, anything goes

?>
```

> 就这些。**Low 档的 PHP 什么都没做。**
> 这一格本身就是结论：**DOM 型的漏洞不在服务器端代码里。**

**② 页面里的内联 `<script>`（★ 真正的那段）—— 藏在 `<select name="default">` 里面：**

```html
<select name="default">
	<script>
		if (document.location.href.indexOf("default=") >= 0) {
			var lang = document.location.href.substring(document.location.href.indexOf("default=")+8);
			document.write("<option value='" + lang + "'>" + decodeURI(lang) + "</option>");
			document.write("<option value='' disabled='disabled'>----</option>");
		}

		document.write("<option value='English'>English</option>");
		document.write("<option value='French'>French</option>");
		document.write("<option value='Spanish'>Spanish</option>");
		document.write("<option value='German'>German</option>");
	</script>
</select>
```

**怎么拿到 ②：** `Ctrl+U`（查看网页源代码）→ `Ctrl+F` 搜 `document.write`

> **顺便：那个 `+8` 不是魔法** —— 字符串 `default=` 正好 **8** 个字符，
> 所以 `substring(indexOf("default=")+8)` 就是"取等号后面的全部内容"。

---

### 2.3 原罪是哪一行 ★

<!-- 提示：三个漏洞的"原罪"是【同一个模式】吗？
     ⚠️ 注意 DOM 型的原罪那一行【不在 PHP 里】，它在 JavaScript 里。
     再想一层：反射型和存储型的原罪行，跟命令注入、SQL 注入的原罪行
     是不是同一个毛病？ -->

| 类型 | 原罪行（贴代码） | 为什么它是原罪 |
|---|---|---|
| 反射型 | echo '<pre>Hello ' . $_GET[ 'name' ] . '</pre>'; | 将输入内容拼接入代码并且没有做数据和代码的隔离 |
| 存储型 | $name = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $name ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : "")); | 同上 |
| DOM 型 | document.write("<option value='" + lang + "'>" + decodeURI(lang) + "</option>"); | （待填 ★ 判断格：`var lang = ...` 只是**取值**，不是原罪；真正把用户输入拼进 HTML 的是这一行。**为什么它是原罪？**（提示：`lang` 进 HTML 之前，做过任何编码吗？）） |

> ### 这是本模块的核心
> 命令注入靠 **shell 的连接符**（`;` `|` `&&`）。
> SQL 注入靠 **SQL 的引号**（`'`）。
> **XSS 靠什么？** —— 而且注意：**XSS 连"特殊符号"都不一定需要。**

XSS注入靠的是'>结束前面的语句，不需要注释掉同一行后面的内容

---

## 3. 复现

> ⚠️ **每一关都要存报文到 `raw/`**，这是 writeup 的证据链。
> 建议命名：`reflected-request.txt` / `reflected-response.txt`（其余同理）

### 3.1 反射型（xss_r）

**第一步：先正常用一次**

```
http://127.0.0.1:8080/vulnerabilities/xss_r/?name=hello
```

**完成标志**：能说出「`hello` 通过 **URL 查询参数 `name`** 传给服务器（GET）」

**第二步：找出 `hello` 落在 HTML 的什么位置**

<!-- 提示：不是"页面上的哪个位置"，是【HTML 源码里】的哪个位置。
     在返回的 HTML 里找到那一行，看 hello 两边是什么。
     是一个标签的文字内容？还是某个属性的值？还是标签名？ -->

```html
<pre>Hello hello</pre>
```

**结论：payload 站在 ——**

文本节点


**第三步：payload**

```
<script>alert(1)</script>
```

**为什么这次不需要任何"逃逸"动作：**

<!-- 提示：HTML 解析器遇到 < 会怎么想？
     它需不需要你先把前面的什么东西"关掉"？ -->

文本态遇<即开标签

**原始请求：**（`raw/reflected-request.txt`）

```http
GET /vulnerabilities/xss_r/?name=%3Cscript%3Ealert%281%29%3C%2Fscript%3E HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36
Accept-Encoding: identity
Accept: */*
Connection: keep-alive
Cookie: PHPSESSID=lhb4gkgv5trne0rp7o7e2epns2; security=low
```

**原始响应（关键部分）：**（`raw/reflected-response.txt`）

```http
HTTP/1.1 200 OK

<html xmlns="http://www.w3.org/1999/xhtml">

<pre>Hello <script>alert(1)</script></pre>

```

**找到的关键那行：**

```html
<pre>Hello <script>alert(1)</script></pre>
原封不动吐出来了，没有转义
```

---

### 3.2 存储型（xss_s）

**第一步：先正常发一条留言**

`http://127.0.0.1:8080/vulnerabilities/xss_s/`

填上 Name / Message → Sign Guestbook。

**第二步：撞墙 —— 客户端限制**

<!-- 表单里的两个客户端限制（从页面 HTML 里抄） -->

```html
<input name="txtName" type="text" size="30" maxlength="10"></td>
				</tr>
				<tr>
					<td width="100">Message *</td>
					<td><textarea name="mtxMessage" cols="50" rows="3" maxlength="50"></textarea></td>
				</tr>
				<tr>
					<td width="100">&nbsp;</td>
					<td>
						<input name="btnSign" type="submit" value="Sign Guestbook" onclick="return validateGuestbookForm(this.form);" />
						<input name="btnClear" type="submit" value="Clear Guestbook" onClick="return confirmClearGuestbook();" />
					</td>
				</tr>
			</table>

		</form>
```

> ⚠️ 这里原先误贴成了 `xss_s` 的 **PHP 源码** —— 那是 §2.2（2）的内容，不是表单。
> 已修正。两个限制是 **`maxlength="10"`**（Name）和 **`maxlength="50"`**（Message）。

**实测：输入超长 payload 时发生了什么？**

**实测：输入超长 payload 时发生了什么？**

浏览器阻止了

**★ 绕过：为什么 `maxlength` 拦不住我**

<!-- 提示：maxlength 是谁在执行的？是浏览器还是服务器？
     服务器有没有可能根本不知道有这个限制？
     那我们用什么工具【跳过浏览器】直接跟服务器说话？ -->

maxlength是浏览器在执行，服务器可能不知道有这个限制。我们可以用repeater代替浏览器发送请求来绕过它。

**原始请求：**（`raw/stored-request.txt`）

```http
POST /vulnerabilities/xss_s/ HTTP/1.1
Host: 127.0.0.1:8080
Content-Length: 75
Cache-Control: max-age=0
sec-ch-ua: "Chromium";v="151", "Not=A?Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Accept-Language: zh-CN,zh;q=0.9
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36
Origin: http://127.0.0.1:8080
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: http://127.0.0.1:8080/vulnerabilities/xss_s/
Accept-Encoding: gzip, deflate, br
Cookie: PHPSESSID=v5et1sgl7cfn3oadi66vmo66d6; security=low
Connection: keep-alive

txtName=txtName&mtxMessage=<script>alert(1)</script>&btnSign=Sign+Guestbook
```

**原始响应（关键部分）：**（`raw/stored-response.txt`）

```http
<div id="guestbook_comments">Name: x<br />Message: <script>alert(1)</script><br /></div>
```

**第三步：证明"它真的存下来了"**

<!-- 提示：只看自己弹窗不算数 —— 那可能只是这一次的响应回显。
     要证明存在服务器上，得让"另一个从来不认识我的人"也中招。
     怎么做？（换个浏览器 / 清掉 cookie / 退出登录再看） -->

| 验证方式 | 结果 |
|---|---|
| 刷新网页 | 弹窗出现（⚠️ 但这**不算证据** —— 响应本身就回显了 payload，说不清它是"存下来的"还是"这一次回显的"） |
| **换一个全新会话**（= "换浏览器"） | **payload 在页面里出现 3 次** —— 这个会话从没提交过任何东西，它却看到了 payload |

> **为什么第二种才算证据**：新会话**不可能**拿到"我这次提交的响应"，
> 它唯一能读到 payload 的地方就是 **数据库**。
> （出处：2026-09-27 用全新 `PHPSESSID` 登录后打开留言板实测）

**★ 存储型跟反射型的本质区别：**

<!-- ★ 判断格（§3.2 唯一的判断题，请自己写）

     三个小问帮你定位：
     ① 反射型的 payload 待在哪儿？—— 提示：它只在【一次响应的路上】
     ② 存储型的 payload 待在哪儿？—— 提示：它被写进了什么？
     ③ 所以受害者要做什么才会中招？
        反射型要"点攻击者给的那个链接"，存储型呢？受害者需要点任何东西吗？
-->

（待填 ★ 判断格）

---

### 3.3 DOM 型（xss_d）

**第一步：先读源码（见 §2.2），搞清楚 JavaScript 干了什么**

<!-- 提示：源码里有几件事要盯住：
     ① 它从 URL 的哪个部分取值？
     ② 它把取到的值【拼进了什么】？（看那一行是不是 innerHTML）
     ③ 服务器在这个过程里参与了哪一步？ -->

这段代码从 URL 里 `default=` 之后取值，拼进了 `<option value='...'>`。

**三个小问，逐个补全：**

| 问题 | 答案 |
|---|---|
| ① 从 URL 的哪个部分取值？ | **`document.location.href`** —— 也就是**浏览器地址栏**。注意：**这不是服务器给的数据** |
| ② 把值拼进了什么？ | `document.write(...)` 写进 DOM 的 **`<option value='...'>` 属性值里** |
| ③ 服务器在这个过程里参与了哪一步？ | **一步都没参与。** 它只是把这段**固定不变的 JS** 当文本发出去；<br>真正读地址栏、真正拼接的，全是**浏览器** |

**第二步：为什么 payload 要多一段 `'>`**

<!-- 提示：看 JS 拼出来的那行 HTML，你的输入落在 <option value='...'> 的哪里。
     属性里的内容是"数据"还是"代码"？想变成代码要先做几件事？ -->

**逐字符拆解 payload（一步都不能少）：**

<!-- 提示：payload 是 '><script>alert(1)</script>
     把 JS 拼出来的那行 HTML 写在下面，再标出每个字符关掉了什么、开启了什么。 -->

**代入 `lang = '><script>alert(1)</script>`，JS 拼出来的字符串是：**

```html
<option value=''><script>alert(1)</script>'>'><script>alert(1)</script></option>
                └────── ① ──────┘   └────── ②（lang 被用到了两次）──────┘
```

**浏览器解析这串文字之后，DOM 里长这样：**

```html
<option value="">
	<script>alert(1)</script>'&gt;'&gt;<script>alert(1)</script>
</option>
```

> **★ 顺带一个发现**：`lang` 在那行模板里出现了**两次**，所以 `<script>` 元素有 **2 个** ——
> **这个 payload 会弹两次 alert。**（实测：解析后 `<script>` 元素个数 = 2，`option` 的 `value` = `""`）

**逐字符拆解（这一步是判断题，自己写）：**

| 字符 | 关掉了什么 / 开启了什么 |
|---|---|
| `'` | （待填 ★ 判断格） |
| `>` | （待填 ★ 判断格） |
| `<script>…</script>` | （待填 ★ 判断格） |

**第三步：★ 本模块最重要的实验 —— 服务器知道这件事吗？**

**实验方法：** 同一个页面，发三次请求，对比服务器返回的 HTML

<!-- 提示：你已经做过了。把三次的 md5 / 字节数补上。 -->

| 请求 | 服务器返回的 HTML 里有 payload 吗 | md5 / 字节数 |
|---|---|---|
| `?default=English`（正常） | **没有** | `93837b07cb7801362da9ba7bc006d468` ／ **4808 字节** |
| `?default=<payload>` | **没有**（`alert` 出现 **0** 次） | **同上，同一个 md5** ／ 4808 字节 |
| `#default=<payload>` | **没有** | **还是同一个 md5** ／ 4808 字节 |

> ★ **这三行被独立复现过两次**：
> 第一次是学生 2026-09-26 自己测的（`93837b07cb78`，4808 字节），
> 第二次是 2026-09-27 抓包脚本测的（`93837b07cb7801362da9ba7bc006d468`，4808 字节）。
> **两次结果完全一致** —— 证据链比单次测量强得多。
> 原始报文：`raw/dom-request.txt` / `raw/dom-response.txt`

**结论：**

<!-- ★ 判断格
     三次返回的**字节一模一样**，页面行为却变了。
     服务器的输出没变 → 变的是浏览器里的东西 → 那只可能是谁干的？ -->

（待填 ★ 判断格）

> ### 这就是"DOM 型"的意义
> **服务器返回的字节里没有 payload，漏洞却真实存在。**
> 那么 —— **服务器日志里会有痕迹吗？**（这个问题留到 §8）

**第四步：`?` 和 `#` 的区别**

<!-- ★ 判断格
     日志服务器实测：访问 /normal?default=AAA#default=BBB，它只收到
         path = /normal?default=AAA
     `BBB` 不见了。三个小问：
     ① `#` 后面的部分叫什么？（一个英文词，安全圈天天用）
     ② 它是给谁用的 —— 服务器，还是浏览器？
     ③ 所以它会出现在服务器的 access.log 里吗？
-->

（待填 ★ 判断格）

**原始请求 / 响应：**（`raw/dom-request.txt` / `raw/dom-response.txt`）

```http
GET /vulnerabilities/xss_d/?default=%27%3E%3Cscript%3Ealert%281%29%3C%2Fscript%3E HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36
Accept-Encoding: identity
Cookie: PHPSESSID=t2o5rgi2rtt3c4havcfgnuv3q1; security=low

HTTP/1.1 200 OK
Content-Length: 4808
Connection: Close
Content-Type: text/html;charset=utf-8

（响应全文 4808 字节，payload 出现 0 次）
```

> **这一栏要记的不是"内容"，而是"没有内容"这件事本身。**
> 服务器发来的字节里根本没提过 payload —— 这正是 DOM 型的签名字特征。

---

## 4. 重点专题：payload 站在哪，决定要不要"逃" ★

<!-- 提示：这一节是这一关真正学到手的东西 —— 它可迁移到后面所有注入类漏洞。
     你今天的两个 payload 长得完全不一样，原因只有一个：落点不同。 -->

### 4.1 三种 HTML 上下文

| 落点 | 例子 | 我的输入是"数据"还是"代码" | 要不要逃 | 怎么逃 |
|---|---|---|---|---|
| 文本节点 | `<pre>Hello ___</pre>` | （待填） | （待填） | （待填） |
| 属性值 | `<option value='___'>` | （待填） | （待填） | （待填） |
| 脚本块 | `<script>var a='___'</script>` | （待填） | （待填） | （待填） |

### 4.2 为什么反射型可以"直接写 `<script>`"

<!-- 提示：这里要讲"解析器容错性"。
     HTML 解析器遇到一个没闭合的标签会怎么样？（想想现实里网页经常写得很烂）
     而 SQL 解析器遇到一个没配对的引号会怎么样？
     而 JS 解析器遇到一个没闭合的字符串会怎么样？ -->

| 解析器 | 遇到残缺输入时的行为 | 后果 |
|---|---|---|
| **HTML** | （待填） | （待填） |
| **SQL** | （待填） | （待填） |
| **JS** | （待填） | （待填） |

**所以：**

- 反射型 payload 为什么**不需要**注释掉后面的 HTML？
- SQL 注入 payload 为什么**必须**加 `#` 或 `-- `？
- JS 相关注入（后面的 XSS 高阶、JavaScript 那一关）为什么可能要用 `//`？

（待填）

### 4.3 属性逃逸的通用套路

<!-- 提示：这是一张"通用地图"，DOM 型只是它的一个实例。
     记住这四步：关引号 → 关标签 → 开新标签 → 写代码 -->

```text
[关属性引号] [关当前标签] [开新标签] [写代码]
     '            >       <script>    alert(1)</script>
```

**如果属性用的是双引号会怎样？**（`value="___"`）

（待填：payload 该怎么改）

**如果没有引号呢？**（`value=___`）

<!-- 提示：现实里很常见 —— 那种情况下 payload 起点是什么？ -->

（待填）

---

## 5. 从 `alert(1)` 到真实危害 ★

<!-- 提示：`alert(1)` 只是"证明我能执行 JS"，它本身不造成损失。
     面试官一定会追问："弹个窗有什么用？"
     这一节就是把 PoC 补成完整的攻击链。

     你手上有一个现成的收数据的道具 —— 阶段 1 你写过的那个日志服务器。 -->

### 5.1 攻击链（写清楚，不用动手）

```text
注入 JS
  → 读取 document.cookie（会话凭证）
  → 发到自己控制的服务器
  → 拿这个 cookie 冒充受害者登录
```

**每一步依赖什么条件？**

| 步骤 | 依赖 | 如果这个条件不成立会怎样 |
|---|---|---|
| 读到 `document.cookie` | （待填：想一个 cookie 属性） | （待填） |
| 把数据发出去 | （待填） | （待填） |
| 用 cookie 冒充身份 | （待填） | （待填） |

### 5.2 为什么"存储型"的评级通常更高

（待填）

### 5.3 【选做·加分】真的偷一次 cookie

<!-- 提示：
     你有一个日志服务器（阶段 1 写的），把它跑起来，监听 127.0.0.1:18099。
     payload 的目标：不弹窗，而是【让浏览器偷偷发一个请求】。
     想想：怎么用 JS 发一个"用户看不见"的请求？
     （new Image().src = '...' 是一个经典手法 —— 因为图片加载失败不会有提示）
     URL 后面用 ?c= 把 cookie 拼上去。
     然后去日志服务器那边，看它有没有收到。 -->

（待填 / 不做就写「未做」）

---

## 6. 根因

<!-- 提示：不要写"没过滤特殊字符"。
     要写：服务端（或前端）把用户输入当成了什么。
     而且这次要写【两遍】—— 服务器端一遍，浏览器端一遍。 -->

| 类型 | 根因 |
|---|---|
| 反射型 | 服务器把本次请求中的输入原样拼进了HTML响应，浏览器的HTML解析器把它当作代码执行，缺了HTML实体编码 |
| 存储型 | 输入被存进数据库，之后又被原样拼进HTML，防护只在SQL层做了转义，HTML层没有防护 |
| **DOM 型** | 浏览器的js把url里的输入原样拼进了DOM，全程没有服务器参与 |

---

## 7. 修复方案

### 7.1 错误做法 —— 为什么"过滤 `<script>`"不算修

<!-- 提示：试试这几种，看能不能绕过"只过滤 <script>"：
     <img src=x onerror=alert(1)>
     <svg onload=alert(1)>
     <ScRiPt>alert(1)</ScRiPt>
     <scr<script>ipt>alert(1)</script>
     想清楚每一招绕的是什么。 -->

| 绕过手法 | 绕过了什么 |
|---|---|
| （待填） | （待填） |

**结论：** 黑名单为什么防不住？

（待填）

### 7.2 正确做法：输出编码（Output Encoding）

<!-- Impossible 档（xss_r）的关键就是这一行 -->

**对比 Low 档和 Impossible 档（差别只有一行）：**

```php
// ---------- Low：原样使用 ----------
$name = $_GET[ 'name' ];
echo '<pre>Hello ' . $_GET[ 'name' ] . '</pre>';

// ---------- Impossible：先编码，再使用 ----------
$name = htmlspecialchars( $_GET[ 'name' ] );
echo "<pre>Hello ${name}</pre>";
```

**★ 那一行就是：**

```php
$name = htmlspecialchars( $_GET[ 'name' ] );
```

**`htmlspecialchars()` 把什么变成了什么：**

| 原字符 | 编码后 |
|---|---|
| `&` | `&amp;` |
| `<` | `&lt;` |
| `>` | `&gt;` |
| `"` | `&quot;` |
| `'` | `&#039;` |

> 所以 `<script>alert(1)</script>` 会变成
> `&lt;script&gt;alert(1)&lt;/script&gt;` ——
> **浏览器把它当【文字】显示，而不是当【代码】执行。**

> **顺带看 `xss_s` 的 Impossible 档，它多做了两件事：**
> `htmlspecialchars()` **加上** PDO 预处理（`$db->prepare()` + `bindParam()`）。
> 也就是说**两个层面的问题，用两套解法**：
> `mysqli_real_escape_string` 管 **SQL**，`htmlspecialchars` 管 **HTML**。
> **（这正好反证了 Low 档的问题 —— 它只做了前者，对 XSS 一点用没有。）**

**为什么这叫"按上下文编码"：**

<!-- ★ 判断格
     同一个用户输入，放到不同位置，要编码成不同的东西：
       · 放进 HTML 文本 / 标签之间 → 编码成什么？（Impossible 档用的就是它）
       · 放进 value="..." 属性里   → 还要多管一个什么字符？
       · 放进 <script>var a='...'</script> 里 → 用 HTML 编码还有用吗？
     再想一层：既然如此，"在入口处统一过滤一遍"为什么天生就是错的？
       （提示：站在入口的时候，你还不知道这个数据最终会去哪个位置） -->

（待填 ★ 判断格）

### 7.3 DOM 型怎么修（这次不在服务器）

<!-- 提示：问题在 JS 那一行。innerHTML 是"把字符串当 HTML 解析"。
     那有没有"把字符串当纯文本"的写法？ -->

| 危险写法 | 安全写法 |
|---|---|
| （待填） | （待填） |

### 7.4 三种类型的修复位置对照 ★

<!-- 提示：这一张表是面试里最能体现"我懂原理"的东西。 -->

| 类型 | 修在哪一层 | 具体手段 |
|---|---|---|
| 反射型 | （待填） | （待填） |
| 存储型 | （待填） | （待填） |
| DOM 型 | （待填） | （待填） |
| 纵深防御（三种都受益） | （待填：想一个响应头） | （待填） |

---

## 8. 日志特征 ★

### 8.1 三种 XSS 在 access.log 里的可见性

<!-- 提示：三种类型的 payload 位置不同 → 日志痕迹完全不同。
     这一张表是本篇最有价值的部分之一。 -->

| 类型 | 提交方式 | payload 在请求的哪一部分 | access.log 里看得见吗 |
|---|---|---|---|
| 反射型 | **GET** | **URL 查询串**（在请求行里） | （待填 ★） |
| 存储型 | **POST** | **请求体（body）** | （待填 ★） |
| DOM 型 | GET，或**只在 fragment 里** | URL ／ **fragment** | （待填 ★） |

> 前两列已经填好（机械事实）。**最后一列是判断题 —— 你已经在 §3.3 第四步想清楚了。**

**从 `logs/dvwa-access.log` 里筛出你这次 XSS 的痕迹（贴一行）：**

```text
（⬜ 待办：当前 logs/dvwa-access.log 是 09-26 15:47 导出的 —— 实测里面 xss_r / xss_s / xss_d 各 0 行，
  因为 XSS 的请求发生在它之后。重新导出一份再筛：

    docker cp dvwa:/var/log/apache2/access.log D:\Code\web-security-lab\logs\dvwa-access.log

  然后：

    Select-String -Path logs\dvwa-access.log -Pattern 'xss_r|xss_s' | Select-Object -First 3）
```

### 8.2 `#` 后面的东西，日志里为什么永远看不到

<!-- 提示：你已经用日志服务器实测过了。把那个实验的结论写清楚：
     请求 URL 是 /normal?default=AAA#default=BBB，
     日志里收到的是 ____。
     原因：`#` 叫 ____，它的用途是 ____，所以浏览器根本不会把它发出去。 -->

（待填）

### 8.3 我的检测工具能抓到吗

<!-- 提示：`loganalyze.py` 现有的规则里，
     `[6]` 只在 query 里有 %27 且含 SQL 关键字时才报 —— XSS 的 payload 会被漏掉。
     那该加什么规则？XSS payload 有哪些"正常请求几乎不会出现"的特征？
     （<script> / %3Cscript%3E / onerror= / onload= / alert( / javascript: ...）
     ⚠️ 注意上次那个假阴性 bug 的教训 —— 关键字大小写怎么办？ -->

（待填）

### 8.4 这条日志能教给我们什么

<!-- 提示：把 §8.1 那张表往上抽象一层。
     同样是"能在浏览器里执行代码"的漏洞，
     三种变体在日志里的可见性却是 ✅ / ❌ / ❌。
     那么"日志能不能做安全分析"的边界到底在哪？
     ⚠️ 而且 DOM 型这一条更狠：它连【服务器完全没参与】都能算 XSS。 -->

（待填）

---

## 9. 遗留问题

- [ ] Medium / High 档未打（会开始过滤 `<script>` 关键字）
- [ ] 【选做】§5.3 真实 cookie 窃取实验
- [ ] `loganalyze.py` 的 XSS 检测规则（T17）

---

## 附：环境噪声记录

<!-- 提示：记下那些"差点让我得出错误结论"的干扰项。
     比如：DOM 型用 ?default= 和 #default= 都能弹窗这件事，
     一开始可能被误读成"服务器也处理了 fragment"。 -->

| 现象 | 原因 | 影响 |
|---|---|---|
| （待填） | （待填） | （待填） |
