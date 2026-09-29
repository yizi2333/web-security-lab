# CSRF（跨站请求伪造）— DVWA

> 靶场：`vulnerables/web-dvwa`（DVWA v1.10 *Development*）
> 难度：Low ✅ ／ Medium ⬜ ／ High ⬜
> 日期：2026-09-28 ~ 09-29
> 工具：Burp Suite Community v2026.8
> 覆盖：**改密码（password change）**

---

## 📋 使用说明（写完这一篇就可以删掉这一段）

**进度条 = 跑下面这条命令，看它输出几。目标：0。**

```powershell
cd D:\Code\web-security-lab
(Select-String -Path writeups\05-csrf\README.md -Pattern ('待'+'填') -AllMatches).Matches.Count
```

> §4 那张 33 格的对照表、以及 §7.5 的 16 格，都已经填好了 —— **剩下的大多是「一句话判断」。**

**建议顺序（别从头顺着填）：**

| 轮次 | 章节 | 干什么 | 类型 |
|---|---|---|---|
| **A** | §3 → §4 的"结论" | 复现 + 看两份报文得出"服务器分不出来" | 一半抄一半想 |
| **B** | §6 → §7 | 根因 + 修复（**本篇的骨头**） | 想 |
| **C** | §0 → §8 → §附 | 总结 + 日志 + 噪声 | 想 |
| **D** | §2.2 → §5 | 原罪行的"缺席"形态 + 危害放大 | 想 |

**★ 全部 72 格里，真正"要想"的集中在 §6 / §7 / §8 —— 那三节写好了，这篇就成立。**

### ★ 这一关跟前面四关有**两个根本区别**，先读这三句再动手

```text
① 漏洞类别不同：前四关是【输入处理类】，这一关是【授权类】
   → 前四关问"我能不能让数据变成代码"
   → 这一关问"我能不能借你的身份，发一个你没打算发的请求"

② 原罪行的形态不同：前四关是"某一行拼接"，这一关是"【缺少一行检查】"

③ 证据形态不同：前四关看"响应里有没有我的 payload"
   → 这一关看"一个我没发起的请求，改变了状态"
```

**⚠️ `raw/csrf-response.txt` 还是 0 字节** —— 补上（Burp 里那一发的 Response 面板）。

---

## 0. 一句话总结

<!-- 提示：跟 XSS 对比着写。三句话讲清：
       ① CSRF 让攻击者能干什么（读？还是写？）
       ② 它需要目标站有"注入点"吗？
       ③ 服务器凭什么被骗？（关键：它把"带着有效 cookie"当成了什么？）
-->

（待填）

---

## 1. 环境

| 项 | 值 |
|---|---|
| 靶场镜像 | `vulnerables/web-dvwa` |
| 入口 | `http://127.0.0.1:8080/vulnerabilities/csrf/` |
| 服务端 | Apache 2.4.25 (Debian) ／ PHP 7.0.30 ／ MariaDB |
| 工具 | Burp Suite Community v2026.8（代理 `127.0.0.1:8081`） |
| **攻击页服务器** | `http://127.0.0.1:18100/`（Python 起的静态服务器） |

### ★ 这一关的"环境"比前几关更重要 —— 因为它决定攻击能不能成

| 项 | 值 | 为什么重要 |
|---|---|---|
| 攻击页的源 | `http://127.0.0.1:18100` | 跟目标是**同主机、不同端口** |
| 与目标的关系 | **跨源**（SOP 认为）／ **同站**（SameSite 认为） | ★ 这两个判断不一样，见 §4 |
| 目标 cookie 的属性 | `path=/`，**没有 `HttpOnly`、没有 `SameSite`** | 所以它会被静默带上 |

---

## 2. 漏洞原理

### 2.1 服务端代码（Low）

<!-- 粘贴地址：http://127.0.0.1:8080/vulnerabilities/view_source.php?id=csrf&security=low -->

```php
<?php

if( isset( $_GET[ 'Change' ] ) ) {
    // Get input
    $pass_new  = $_GET[ 'password_new' ];
    $pass_conf = $_GET[ 'password_conf' ];

    // Do the passwords match?
    if( $pass_new == $pass_conf ) {
        // They do!
        $pass_new = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $pass_new);
        $pass_new = md5( $pass_new );

        // Update the database
        $insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . dvwaCurrentUser() . "';";
        $result = mysqli_query($GLOBALS["___mysqli_ston"], $insert) or die(...);

        // Feedback for the user
        echo "<pre>Password Changed.</pre>";
    }
    else {
        // Issue with passwords matching
        echo "<pre>Passwords did not match.</pre>";
    }
}

?>
```

### 2.2 ★ 这一关的"原罪行"，形态跟前四关**完全不同**

**前四关的原罪行是【某一行拼接】：**

```php
echo '<pre>Hello ' . $_GET['name'] . '</pre>';               // XSS
$query = "SELECT ... WHERE user_id = '$id';";                // SQLi
shell_exec( 'ping -c 4 ' . $target );                        // 命令注入
```

**这一关的原罪行是【一个缺席的检查】—— 你看不到它，因为它不在代码里。**

<!-- ★ 判断格
     对着上面 2.1 的代码回答：
       ① 它检查了 cookie 吗？（其实它连"检查"都没写 —— 是谁在替它检查？）
       ② 它检查了"这个请求是不是用户想发的"吗？
       ③ 它检查了请求的来源吗？
     然后写一句：这一关的"原罪行"具体是【缺少哪一行】？
       （提示：去 §7.3 看 High 档多出来的那一行 —— 那就是缺的）
-->

（待填 ★）

> ### 一句话记住这个区别
> **前四关：找那一行"把数据和代码拼在一起"的代码。**
> **这一关：找那一行"本该存在却不存在"的检查。**
>
> **所以这一关的 §2 不能靠"抄代码"，要靠"读代码里没有的东西"。**

### 2.3 四档源码对比 —— 修复梯度（这一节是 §7 的地图）

| 档位 | 它加了什么 | 有效性 |
|---|---|---|
| **Low** | **什么都没有** | ❌ 完全裸奔 |
| **Medium** | `stripos( $_SERVER['HTTP_REFERER'], $_SERVER['SERVER_NAME'] ) !== false` | ⚠️ **看起来有用，实测可绕（见 §7.1）** |
| **High** | `checkToken( $_REQUEST['user_token'], $_SESSION['session_token'], 'index.php' )` | ✅ 有效（CSRF Token） |
| **Impossible** | Token **＋ 要求输入当前密码**（`password_current`） | ✅ 最强（**即使 token 泄漏，还需要知道原密码**） |

<!-- ★ 判断格
     看这张表，回答一件事：Medium 和 High 的防御思路【根本不同】在哪？
       提示：一个是"检查请求【从哪来】"，一个是"检查请求【带了什么】"。
     再想：哪种思路更可靠？为什么？
-->

（待填 ★）

---

## 3. 复现

> **这一关的 §3 跟前四关写法完全不同。** 前四关是"输入 payload → 看回显"，
> 这一关是"**让受害者自己把请求发出去**"。所以下面每一步都要留证据。

### 3.1 第 1 步：先正常改一次密码（看它"该"长什么样）

在 DVWA 的 CSRF 页面正常改一次密码，用 Burp 抓下来。

**原始请求：**（`raw/normal-request.txt`）

```http
GET /vulnerabilities/csrf/?password_new=aaaaaa&password_conf=aaaaaa&Change=Change HTTP/1.1
Host: 127.0.0.1:8080
Accept-Language: zh-CN,zh;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: http://127.0.0.1:8080/vulnerabilities/csrf/
Cookie: PHPSESSID=v5et1sgl7cfn3oadi66vmo66d6; security=low
```

**从这一发能看出三件事：**

| 问题 | 答案 |
|---|---|
| 方法是什么？ | **GET**（参数全在 URL 里） |
| 请求里有没有"只有我的页面才知道"的东西？ | **没有**（无 token、无随机数、无隐藏字段） |
| 服务器凭**什么**认我？ | **只有 `Cookie`** |

### 3.2 第 2 步：★ 实验 —— 服务器到底检查了什么、没检查什么

**这一步是本篇最重要的实验**，因为它用对照法把"检查的边界"划出来了。

**技巧：全程用"两次密码不一致"（`aaa` / `bbb`）→ 服务器不会执行 UPDATE → 零副作用，可以随便试。**

| # | 你怎么改请求 | 服务器反应 | 说明 |
|---|---|---|---|
| **A** | 原样发 | `<pre>Passwords did not match.</pre>` | 基线：请求被正常处理 |
| **B** | 加 `Origin: http://evil.example`<br>改 `Referer: http://evil.example/attack.html` | **跟 A 一模一样** | ★ **它不看来源** |
| **C** | **删掉 `Cookie:` 那一整行** | **`302` → `Location: ../../login.php`** | ★ **cookie 是唯一条件** |

**C 的原始响应：**（`raw/no-cookie-response.txt`）

```http
HTTP/1.1 302 Found
Set-Cookie: PHPSESSID=1c0hjscgfju50r0buh7h4gc1d4; path=/
Location: ../../login.php
Content-Length: 0
Content-Type: text/html; charset=UTF-8
```

**★ 从 A/B/C 能得出两句结论（自己写）：**

<!-- ★ 判断格
     ① A 和 B 的反应完全一样，说明服务器不检查【什么】？
     ② C 被踢走，说明 cookie 是【什么】？
     ③ 把①②合起来：服务器的判断逻辑等价于哪一句伪代码？
-->

（待填 ★）

### 3.3 第 3 步：构造攻击页

**这一关的 payload 不是一个字符串，而是【一整个页面】。**

**攻击页：**（`raw/attack-page.html`）

```html
<!DOCTYPE html>
<html lang="zh">
<head><meta charset="utf-8"><title>恭喜中奖！</title></head>
<body>
  <h1>🎉 恭喜你获得一等奖</h1>
  <p>正在为你领取奖品，请稍候……</p>

  <img src="http://127.0.0.1:8080/vulnerabilities/csrf/?password_new=pwned_by_csrf&password_conf=pwned_by_csrf&Change=Change"
       alt="" style="width:1px;height:1px;">
</body>
</html>
```

**★ 整段 payload 的核心只有一行 `<img>`：**

<!-- ★ 判断格
     想想这一行是怎么"变成一次请求"的：
       ① 浏览器看到 <img src="..."> 会做什么？（它想干成什么事？）
       ② 它需要 JavaScript 吗？
       ③ 它需要读响应吗？
     再回答：为什么"禁用 JavaScript"防不住这种攻击？
-->

（待填 ★）

**攻击页的服务器：**

```powershell
cd D:\dsh\_tmp_try_demo
& D:\Code\security-lab\.venv\Scripts\python.exe -m http.server 18100
```

**访问地址（★ 必须是 `127.0.0.1`，不能用 `localhost` —— 原因见 §4）：**

```text
http://127.0.0.1:18100/csrf_attack.html
```

### 3.4 第 4 步：受害者打开它 → 密码被改

**完整攻击链：**

```text
① 受害者在 DVWA 里已登录（浏览器有有效 PHPSESSID）
② 受害者在【同一个浏览器】打开了攻击页
③ 浏览器为了"加载那张图片"，向 127.0.0.1:8080 发出改密码的 GET 请求
   ★ 并且【自动带上】DVWA 的 cookie
④ 服务器：cookie 合法 → 执行 → 密码变成 pwned_by_csrf
⑤ 图片显示成破图，受害者毫无察觉
⑥ 攻击者用 pwned_by_csrf 登录成功
```

**★ 这里有个反直觉的点：③ 的请求不是 JavaScript 发的，是【浏览器加载图片】这个动作发的。**

### 3.5 ★ 证据链：四份报文怎么互相印证

| 证据 | 它证明什么 |
|---|---|
| `raw/normal-request.txt`<br>`raw/normal-response.txt` | **这个功能本来该长什么样**（人点了按钮，同源导航） |
| `raw/attack-page.html` | **payload 只是一行 `<img>`** —— 不需要 JS、不需要钓鱼页面技术 |
| **`raw/csrf-request.txt`** | ★ **由攻击页触发的那一发，服务器【照样执行了】** |
| `raw/no-cookie-response.txt` | **cookie 是唯一条件**（删掉就被踢走） |

**★ 这四份合起来，构成一个完整闭环：**

```text
"这个功能该长什么样"  +  "它长什么样也能生效"  +  "唯一条件是 cookie"
        ↓
    服务器无法分辨"人点的"和"图片触发的"
```

---

## 4. ★ 重点专题：正常请求 vs 攻击请求，到底差在哪

<!-- ★★★ 这一节是整篇的核心。把 raw/ 里那两份报文并排看，逐行填这张表。
     已经是填空题了，几乎不用"想"，只需要"抄"。
     填完再看表下面那句总结 —— 那就是 §6 根因。 -->

| 请求头 | **正常那一发**（人点的）<br>`raw/normal-request.txt` | **攻击那一发**（`<img>` 触发的）<br>`raw/csrf-request.txt` | 一样吗 |
|---|---|---|---|
| 方法 / 路径 | `GET /vulnerabilities/csrf/` | `GET /vulnerabilities/csrf/` | ✅ **一样** |
| 参数 | `?password_new=aaaaaa&password_conf=aaaaaa&Change=Change` | `?password_new=hacked&password_conf=hacked&Change=Change` | 结构一样，只有值不同 |
| `Host` | `127.0.0.1:8080` | `127.0.0.1:8080` | ✅ **一样** |
| **`Cookie`** | `PHPSESSID=v5et1sgl7cfn3oadi66vmo66d6; security=low` | `PHPSESSID=v5et1sgl7cfn3oadi66vmo66d6; security=low` | ✅ **完全一样** |
| **`Referer`** | `http://127.0.0.1:8080/vulnerabilities/csrf/` | **`http://127.0.0.1:18100/`** | ❌ **不同** |
| **`Sec-Fetch-Site`** | `same-origin` | **`same-site`** | ❌ 不同 |
| **`Sec-Fetch-Mode`** | `navigate` | **`no-cors`** | ❌ 不同 |
| **`Sec-Fetch-Dest`** | `document` | ★ **`image`** | ❌ **不同（最刺眼）** |
| **`Sec-Fetch-User`** | **`?1`** | **（没有这个头）** | ❌ **不同** |
| **`Accept`** | `text/html,application/xhtml+xml,application/xml;q=0.9,...,*/*;q=0.8` | ★ **`image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8`** | ❌ **不同** |
| `Upgrade-Insecure-Requests` | `1` | **（没有）** | ❌ 不同 |
| **服务器反应** | `200` ＋ `<pre>Password Changed.</pre>` | `200` ＋ `<pre>Password Changed.</pre>`<br>（以 `raw/csrf-response.txt` 为准） | ✅ **完全一样** |

> **★ 最后两行是整张表的重点：**
> **`Cookie` 一样，服务器反应一样。**
> **差别全在那些"服务器【不看】的头"里。**

**★ 结论（自己写，这是 §6 根因的直接原料）：**

<!-- ★ 判断格
     看最后一行"服务器反应"—— 两发是不是完全一样？
     再看 `Cookie` 那一行 —— 两发是不是完全一样？
     那么：服务器凭什么分得出来？它**分不出来**，因为它不看哪些头？
-->

（待填 ★）

### 4.1 ★ 顺带一个反直觉的细节：`源` ≠ `站`

**同一个请求里，两个机制给出了不同的判定：**

```text
Sec-Fetch-Site: same-site           ← 对 SameSite 来说：同站
Referer: http://127.0.0.1:18100/    ← 对 referrer 来说：跨源，所以路径被裁掉了
```

| | 判断依据 | 结果 |
|---|---|---|
| **`SameSite`**（cookie 用） | **站** = 主机 | 主机相同 → `same-site` |
| **SOP ／ referrer 裁剪** | **源** = 协议 + 主机 + **端口** | 端口不同 → 跨源 |

<!-- ★ 判断格
     ① 为什么 `Referer` 显示的是 `http://127.0.0.1:18100/`，而不是完整的
        `http://127.0.0.1:18100/csrf_attack.html`？
        （提示：一个叫 Referrer-Policy 的浏览器默认行为）
     ② 这个"裁短"对"用 Referer 做 CSRF 防护"意味着什么？
-->

（待填 ★）

### 4.2 ★ 为什么攻击页必须用 `127.0.0.1`，不能用 `localhost`

<!-- ★ 判断格
     实测过：攻击页从 127.0.0.1:18100 加载 → cookie 带上了；
             从 [::1]:18100 加载        → cookie 一个都没带（Sec-Fetch-Site: cross-site）
     回答：为什么"端口不同"不影响 cookie 的携带，但"主机不同"就会？
       关键词：SameSite=Lax 会拦住"跨站的子资源请求"，而跨不跨站只看____。
-->

（待填 ★）

---

## 5. 从"改密码"到真实危害 ★

<!-- 提示：DVWA 这一关只能改自己的密码，危害看着很小。要把它放大到真实场景。
     想想：一个"靠 cookie 认身份"的网站，还有哪些操作会被 CSRF 打？
     再想：为什么"改密码"其实是很有价值的目标？（提示：改完之后呢？）
-->

**可以被打的典型操作：**

| 操作 | 危害 |
|---|---|
| （待填） | （待填） |

**为什么"改密码"特别值得打：**

<!-- ★ 判断格
     提示：改完密码之后，攻击者就……？而且受害者会怎样？
     （对比一下：如果只是"发一条垃圾动态"，你还能删；密码被改了你能怎样？）
-->

（待填 ★）

**这一关的限制（也让攻击链更真实）：**

| 限制 | 说明 |
|---|---|
| 只能改**自己**的密码 | `WHERE user = dvwaCurrentUser()` —— 目标由 cookie 决定 |
| 响应读不到 | `Sec-Fetch-Mode: no-cors` → 攻击页的 JS 读不到响应 |
| 需要受害者**已登录且在线** | 跟 XSS 偷 cookie 不同，这里攻击者**不需要知道 cookie 是什么** |

---

## 6. 根因

<!-- ★ 判断格（本篇最重要的一句）
     不要写"没做 CSRF 防护"。要写：服务器把【什么】当成了【什么】。
     提示：它把"带着有效 cookie"当成了"用户的真实意图"。
     再补一句：这不是 DVWA 写错了代码，而是当年 Web 的通用状态 ——
              浏览器当年【没有能力】告诉服务器"这发请求是跨站来的"。
-->

（待填 ★）

---

## 7. 修复方案

### 7.1 错误做法：只查 `Referer`（Medium 档）★ 实测可绕

**Medium 档的代码：**

```php
// Checks to see where the request came from
if( stripos( $_SERVER[ 'HTTP_REFERER' ], $_SERVER[ 'SERVER_NAME' ] ) !== false ) {
    ... 正常执行 ...
} else {
    echo "<pre>That request didn't look correct.</pre>";
}
```

**它做的是【字符串包含】，不是【来源判断】。**

**实测（全程用 `aaa`/`bbb` 不匹配，零副作用）：**

| `Referer` 的值 | Medium 档反应 |
|---|---|
| 完全不发 `Referer` | ❌ 挡住 |
| `http://evil.example/attack.html` | ❌ **挡住**（防护确实有效） |
| `http://127.0.0.1:18100/csrf_attack.html` | ★★ **通过**（同主机不同端口） |
| `http://127.0.0.1.evil.example/a.html` | ★★ **通过**（★ 致命的） |

<!-- ★ 判断格
     看第 4 行：`127.0.0.1.evil.example` 是【攻击者能控制的域名】。
       ① 为什么它能通过？（提示：stripos 在找什么？找到了吗？）
       ② "注册一个名字里含受害者主机名的域名"这件事，攻击者做得到吗？
       ③ 正确的做法应该是什么？（提示：不是"找子串"，而是"解析出源，再比较"）
-->

（待填 ★）

> **★ 这跟前面几关的同类错误是一族的：用"字符串包含"代替"语义比较"**
> （对照：`SQLI_KEYWORDS` 大小写、`[regex]::Escape` + `-SimpleMatch`）

**另外 `Referer` 本身就不该被当作可靠依据：**

| 问题 | 说明 |
|---|---|
| 可能被裁短 | Chrome 默认 `strict-origin-when-cross-origin` → 只给源，不给路径（§4.1 实测） |
| 可能被完全去掉 | `Referrer-Policy: no-referrer`、HTTPS→HTTP 降级 |
| 可能缺失 | 用户直接输入 URL、从书签打开 |

### 7.2 正确做法：CSRF Token（High 档）

```php
// Check Anti-CSRF token
checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );
```

**为什么有效：**

<!-- ★ 判断格
     提示：token 存在【服务器端会话】里，同时在【表单页面】上发一份。
     攻击者的页面能不能读到受害者那个页面上的 token？为什么？
     （复习 XSS 那关：同源策略拦的是什么？）
-->

（待填 ★）

> **★ 你已经见过它了** —— 抓 DVWA 登录时第一次失败，就是因为 **`login.php` 要求 `user_token`**。
> **DVWA 自己的登录页有这个防护，CSRF 这一关的 Low 档却没抄过来。**

### 7.3 更强：Token ＋ 二次校验（Impossible 档）

**Impossible 档多要了一样东西：**

```php
$pass_curr = $_GET[ 'password_current' ];
...
if( ( $pass_new == $pass_conf ) && ( $data->rowCount() == 1 ) ) {   // 当前密码必须正确
```

<!-- ★ 判断格
     它加的是"必须输入当前密码"。这挡住的**不是 CSRF**（Token 已经挡了），
     那它挡的是什么？（提示：如果攻击者通过别的手段拿到了 token 呢？
                       或者用户误点了钓鱼页面并自己填了密码呢？）
-->

（待填 ★）

### 7.4 浏览器层：`SameSite` cookie

**DVWA 发的 cookie 实测是：**

```http
Set-Cookie: PHPSESSID=...; path=/
Set-Cookie: security=low
```

**没有 `SameSite` 属性** → 现代浏览器按 **`Lax`** 处理。

| 值 | 行为 |
|---|---|
| `SameSite=Strict` | 跨站请求**一律不带** cookie |
| `SameSite=Lax`（默认） | 跨站的 **GET 导航**会带；**子资源请求（`<img>`）不带** |
| `SameSite=None` | 都带（需配 `Secure`） |

<!-- ★ 判断格
     实测过：攻击页从 127.0.0.1:18100 打 127.0.0.1:8080 —— cookie【带上了】。
       ① 因为它算【同站】（SameSite 只看主机）
       ② 那如果攻击者的页面在【别的域名】上，`<img>` 这条路还走得通吗？
       ③ 但 `Lax` 会放行"跨站的 GET 导航" —— 那攻击者能不能改用"让用户点一个链接"的方式？
-->

（待填 ★）

### 7.5 ★ 四种手段对照表（面试用）

| 手段 | 补上的那半边条件是 | 修在哪一层 | 局限（★ 这才是面试会追问的） |
|---|---|---|---|
| **CSRF Token** | "请求里带上了 **我这个页面独有** 的随机串" | **服务端**<br>（会话里存一份、表单里发一份、提交时比对） | ① 每个要防护的表单/接口都要改<br>② AJAX / SPA 要额外处理（token 得能从页面读到再发出去）<br>③ ★ **如果站里同时有 XSS，token 会被读走** —— Token 是"假设没有 XSS"的防护（XSS + CSRF 组合拳） |
| **`SameSite` cookie** | "cookie **只在同站请求里**才被带上" | **浏览器**<br>（服务端只需在 `Set-Cookie` 里加属性） | ① ★ **`Lax` 放行"跨站的 GET 导航"** → 所以"骗你点一个链接"型的 GET CSRF **仍然可能**<br>② `None` 等于没防护<br>③ ★ **它防不住"同站不同源"**（比如同一主机的另一个端口 —— 本文实测的攻击正是这种）<br>④ 老浏览器不支持 |
| **`Origin` 校验** | "这发请求**来自我自己站**" | **服务端**<br>（读 `Origin` 请求头） | ① ★ **某些请求形态根本没有 `Origin` 头** —— 本文抓到的那一发攻击就没有 → 存在盲区<br>② 必须决定"头不存在时"是放行还是拒绝（放行=有洞，拒绝=可能误伤老客户端）<br>③ `Referer` 更不可靠：会被裁短（§4.1）、会被完全去掉 |
| **`Sec-Fetch-Site` 校验** | "**浏览器自己交代了**这发请求的来路" | **服务端**<br>（读 `Sec-Fetch-Site` 头） | ① 只有较新的浏览器才发这个头<br>② 同样要处理"头不存在"的情况<br>③ ★ **优点：页面【无法伪造】**（浏览器自己加，JS 改不了）→ 比 `Referer` 可靠得多 |

> **一句话总结这四种：全都是"让服务器有能力判断——这个请求是不是用户真想发的"。**

### ★ 面试追问预演（填完表别停，先自己答一遍）

**答不上来的，回到括号里指的那一节重读。**

| # | 追问 | 答案在哪 |
|---|---|---|
| 1 | **CSRF 和 XSS 的修复方式能互换吗？为什么？** | §7.2 + XSS 那篇 §7（一个修"输出编码"，一个修"来源/令牌"） |
| 2 | **如果一个站只加了 `SameSite=Lax`，还有什么 CSRF 能打？** | 本表 `SameSite` 行的①（提示：`Lax` 放行什么？） |
| 3 | **为什么不建议用 `Referer` 当主要防护？** | §7.1（两个理由：一是机制上不可靠，二是**实现上用子串匹配就是错的** —— 本文实测绕过） |
| 4 | **`SameSite` 和 `HttpOnly` 分别防什么？** | §7.4 + XSS 那篇 §5.1 |
| 5 | **CSRF 和"偷到 cookie 后冒充"有什么区别？** | `for_ask` 问题 5 那张对照表 |
| 6 | **为什么 DVWA 的 Medium 看起来做了防护，却还是被打穿了？** | §7.1（"字符串包含" ≠ "语义上的同源"） |

---

## 8. 日志特征 ★

### 8.1 这一关的 payload 在请求的哪个部位

| 项 | 值 |
|---|---|
| 方法 | **GET** |
| payload 位置 | **URL 查询串**（`?password_new=...`） |
| 在 `access.log` 里看得见吗 | **✅ 看得见**（在请求行里） |

### 8.2 ★★ 但真正有意思的是这个：**`access.log` 记录 `Referer`**

<!-- ★ 判断格（这一节是这一关最有价值的发现）
     Combined Log Format 记的两样东西是：____ 和 ____。
     （复习第一阶段：你的 loganalyze.py 一共提取了几个字段？其中有没有 Referer？）
-->

（待填 ★）

**所以：CSRF 的攻击痕迹**不在"payload 长什么样"里（那一发看起来完全正常），
**而在 `Referer` 里** —— 因为它是唯一一个"能说明请求从哪来"的被记录字段。

### 8.3 ★ 给 `loganalyze.py` 加第 7 条规则

**这一发攻击在日志里长这样：**

```text
正常那一发：
  172.17.0.1 - - [28/Sep/2026:...] "GET /vulnerabilities/csrf/?password_new=aaaaaa&... HTTP/1.1" 200 4297 "http://127.0.0.1:8080/vulnerabilities/csrf/" "Mozilla/5.0 ..."

攻击那一发：
  172.17.0.1 - - [29/Sep/2026:...] "GET /vulnerabilities/csrf/?password_new=pwned_by_csrf&... HTTP/1.1" 200 4297 "http://127.0.0.1:18100/" "Mozilla/5.0 ..."
                                                                                                                    ↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑
                                                                                                             只有 Referer 变了
```

**规则思路：**

```text
对"敏感操作"的请求（比如 URL 里含 password_new / 改密码相关的路径）：
   如果 Referer 的【源】不等于本站的源  →  告警
```

<!-- ★ 判断格
     这条规则要小心两个坑，各写一句：
       ① Referer 可能为空（用户直接输 URL / 书签 / no-referrer）—— 那该怎么办？
          （提示：告警还是放过？为什么不能一律告警？）
       ② 这跟你前面那条 [6] 规则踩过的坑有什么关系？
          （提示：比字符串包含更可靠的，是比较【解析后的源】还是别的？）
-->

（待填 ★）

### 8.4 日志能不能做安全分析 —— 这一关的边界

<!-- ★ 判断格
     对比一下前几关：
       SQL 注入 / 反射型 XSS  →  payload 本身就是"异常字符串"，很好认
       CSRF                    →  payload 完全正常，只有 Referer 能说话
     那"日志能不能发现 CSRF"取决于什么？
       （提示：取决于日志记不记 Referer。如果目标是"不记 Referer 的日志格式"呢？）
-->

（待填 ★）

---

## 9. 遗留问题

- [ ] **Medium / High 档未打**（Medium 已在 §7.1 被实测绕过；High 要处理 token）
- [ ] **POST 型的 CSRF 没测**（这一关是 GET 型；POST 型要用"自动提交的隐藏表单"）
- [ ] `Origin` 头在 GET/POST 跨源请求里的有无差异，没系统验证（见 §附）
- [ ] `loganalyze.py` 第 7 条规则未实现
- [ ] 打完这一关要把 DVWA 密码 Reset 回去（现在是 `aaaaaa`）

---

## 附：环境噪声记录

| 现象 | 原因 | 影响 |
|---|---|---|
| （待填） | （待填） | （待填） |
| （待填） | （待填） | （待填） |
| （待填） | （待填） | （待填） |

<!-- 提示：这一关你有三个特别好的素材：
     ① 从 [::1]:18100 加载攻击页时，cookie 一个都没带 —— 但请求照样发出去了、页面也正常显示。
        如果不看 Sec-Fetch-Site 头，你会以为"CSRF 在这个站不成立"，其实是浏览器在保护。
        （这是"静默失效"的又一个变体：拦截不报错）
     ② `Referer` 被裁短成只有源 —— 差点以为"Referer 没传成功"。
     ③ 助手（我）用"PHPSESSID 是几天前的"推断"你在看旧历史"，**推错了** ——
        因为那个会话 cookie 一直在用。两次贴给我的请求都是【对的格式但错的对象】。
-->
