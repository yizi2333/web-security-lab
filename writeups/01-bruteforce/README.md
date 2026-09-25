# 暴力破解（Brute Force）— DVWA

> 靶场：`vulnerables/web-dvwa`（DVWA v1.10 *Development*）
> 难度：Low ✅ ／ Medium ⬜ ／ High ⬜
> 日期：2026-09-23
> 工具：Burp Suite Community v2026.8

---

## 0. 一句话总结

**爆破的前提，是先找到一个能可靠区分「成功」和「失败」的判据 ——
而判据没有通用答案，每个应用都要重新找。**

字典大小、跑得多快，都是次要的。

---

## 1. 环境

| 项 | 值 |
|---|---|
| 靶场镜像 | `vulnerables/web-dvwa` |
| 入口 | `http://127.0.0.1:8080/vulnerabilities/brute/` |
| 服务端 | Apache 2.4.25 (Debian) ／ PHP 7.0.30 |
| 工具 | Burp Suite Community v2026.8（Intruder + Repeater） |
| 字典 | `wordlists/passwords.txt`（53 条，`password` 在第 48 位） |

---

## 2. 这一关是什么

### 2.1 服务端代码（Low）

```php
<?php

if( isset( $_GET[ 'Login' ] ) ) {
    // Get username
    $user = $_GET[ 'username' ];

    // Get password
    $pass = $_GET[ 'password' ];
    $pass = md5( $pass );

    // Check the database
    $query  = "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';";
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ... . '</pre>' );

    if( $result && mysqli_num_rows( $result ) == 1 ) {
        // Login successful
        echo "<p>Welcome to the password protected area {$user}</p>";
        echo "<img src=\"{$avatar}\" />";
    }
    else {
        // Login failed
        echo "<pre><br />Username and/or password incorrect.</pre>";
    }
}

?>
```

**两个细节值得注意：**

1. **`$pass = md5( $pass );`** —— 数据库里存的是密码的 md5 哈希，不是明文。
   但 `md5()` 在**服务端**执行，所以**传输时密码仍然是明文**（抓包能看到）。
2. **`$query` 是字符串拼接** —— `$user` 被直接拼进 SQL，**这里还藏着一个 SQL 注入**。
   同一段代码，换个用法就是另一个洞。

### 2.2 它为什么**能被**爆破

这个登陆接口并没有速率限制、账号锁定、验证码或者失败延迟。这就意味着如果获得了一个存在的用户名我们可以使用字典攻击爆破，猜出正确密码。

---

## 3. 复现

### 3.1 第一步：先找「判据」★

> **这是这一篇的核心。** 爆破的前提不是"字典大"，而是
> **「你能可靠地区分登录成功和登录失败」**。
> 区分不了，字典再大也是白跑。

**DVWA 里有两个"输入用户名密码"的地方，判据完全不同：**

| | `POST /login.php`（登录页） | `GET /vulnerabilities/brute/`（爆破模块） |
|---|---|---|
| 状态码 | 302（成功失败**都一样**） | 200（**都一样**） |
| 响应体长度 | **0 字节**（**都一样**） | 4703（失败）／4741（成功） |
| **靠什么区分** | **`Location` 头** | **响应体长度 / 响应里的关键词** |

**实测数据：**

```text
login.php
  成功 → 302, 响应体 0 字节, Location: index.php
  失败 → 302, 响应体 0 字节, Location: login.php

brute/
  失败 → 200, Burp Length = 4703
  成功 → 200, Burp Length = 4741
```

**为什么两个判据不一样？**

**因为两个页面的「实现方式」不同：**

- `login.php` 用 **302 重定向**跳转 —— 信息藏在 **`Location` 头**里，响应体是空的
- `brute/` 直接在**页面里输出文本** —— 信息藏在**响应体**里

> **所以"判据"没有通用答案，每个应用都得重新找。**
> 而且要注意：**"都一样"和"不一样"同等重要** ——
> `login.php` 是"状态码一样、长度一样"，**只剩 `Location` 可看**；
> `brute/` 是"状态码一样、长度不同"，**才能看长度**。

**原始报文：**

`raw/login-request.txt`（**成功**那条）：

```http
POST /login.php HTTP/1.1
Host: 127.0.0.1:8080
Content-Length: 88
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36
Origin: http://127.0.0.1:8080
Referer: http://127.0.0.1:8080/login.php
Cookie: PHPSESSID=rbbnph18g1eu24m08di9u2ft71; security=low
Connection: keep-alive

username=admin&password=password&Login=Login&user_token=b79c181da318f7039735f3b75f16c918
```

`raw/login-response.txt`（**成功**）：

```http
HTTP/1.1 302 Found
Date: Wed, 23 Sep 2026 15:07:57 GMT
Server: Apache/2.4.25 (Debian)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: index.php
Content-Length: 0
Content-Type: text/html; charset=UTF-8
```

> **失败那条没存报文** —— 但实测结果是 `Location: login.php`。
> 两次唯一的差别就是 `Location` 的值。

`raw/brute-success-request.txt`：

```http
GET /vulnerabilities/brute/?username=admin&password=password&Login=Login HTTP/1.1
Host: 127.0.0.1:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36
Referer: http://127.0.0.1:8080/vulnerabilities/brute/
Cookie: security=low; PHPSESSID=v5et1sgl7cfn3oadi66vmo66d6; security=medium
Connection: keep-alive
```

> **注意两件事：**
> ① **密码明文在 URL 里** —— GET 提交的后果（`§8` 会讲）
> ② **Cookie 里 `security` 出现了两次** —— 见文末「环境噪声记录」

`raw/brute-success-response.txt`（关键部分，其余 100 余行页面模板已省略）：

```http
HTTP/1.1 200 OK
Date: Thu, 24 Sep 2026 02:23:53 GMT
Server: Apache/2.4.25 (Debian)
Content-Length: 4413
Content-Type: text/html;charset=utf-8

...

<div class="body_padded">
	<h1>Vulnerability: Brute Force</h1>
	<div class="vulnerable_code_area">
		<h2>Login</h2>
		<form action="#" method="GET">
			<input type="text" name="username"><br />
			<input type="password" AUTOCOMPLETE="off" name="password"><br />
			<input type="submit" value="Login" name="Login">
		</form>
		<p>Welcome to the password protected area admin</p><img src="/hackable/users/admin.jpg" />
	</div>
</div>
```

> **`Welcome to the password protected area` 这一行就是判据。**

### 3.2 第二步：用 Burp Intruder 跑字典

**操作步骤：**

1. **标载荷位置**：在 `password=` 后面的值上标记（Burp 里显示为 `§a§` 的样子）
2. **载入载荷**：通过 `payload configuration`，添加本地字典路径
3. **开跑并看结果**：点 `start attack`，在 `Intruder/results` 界面查看，**通过寻找与其他不同的 `Length`**

**载荷位置（这一步最容易错）：**

```http
GET /vulnerabilities/brute/?username=admin&password=§a§&Login=Login HTTP/1.1
                                              ↑ 只能有这一个 §
```

**⚠️ 如果标了不止一个位置**，Intruder 会做**笛卡尔积**（53 × 53 = 2809 次），
而且**它不会报错** —— 结果全是乱的。

> 「笛卡尔积」就是两个集合的所有两两组合：用户名 53 个 × 密码 53 个 = 2809 种搭配。
> **跟我在 `portscan.py` 里写的那句 `for host in targets for port in ports` 是同一个东西** ——
> 254 个主机 × 3 个端口 = 762 个扫描任务。

**结果怎么看：**

| 方法 | 怎么做 | 优缺点 |
|---|---|---|
| 点 `Length` 列排序 | 在 `Intruder/results` 界面点击 `Length` | 方便，但是不完全可信 |
| `Grep - Match` 加关键词 | 在 `Grep - Match` 添加 `welcome` 关键词然后进行工具 | 稍微麻烦，但是可信度高很多 |

**为什么推荐第二种？**

因为 Length 不同的原因可能是多样的，导致结果不可信。

**具体地：** 两个不同的密码，一个让页面多出 50 字节、另一个少 50 字节，
**净长度可能刚好撞上同一个值** —— 这时按长度排序会看到两个"可疑"的，没法判断。

**而 `Welcome` 这个词只有登录成功才出现**（实测：失败页 0 次，成功页 1 次）。**内容不会骗人。**

### 3.3 结果

```
Payload: password
成功那条的 Length: 4741
```

---

## 4. 一个必须记下的教训：53 行废数据 ★

**我第一次跑 Intruder 时，53 条结果全是废的。**

```
[结果表]
0    123456        200   4703
1    12345678      200   4703
...
52   guest         200   4703      ← 全是 4703, 一条不同的都没有
```

**Burp 没报任何错。** 状态是 `Finished`，53 个请求全都返回 200，表格整整齐齐。

**但全部无效。**

**原因：**

第一次攻击时填的是无效的用户名（并非 `admin`）。

所以字典里的密码再怎么试也没用 —— 服务器会因为「用户名不对」而全部拒绝，
**53 条全都是同一个失败页面（长度 4703）。**

**为什么这个教训比"成功案例"值钱：**

**因为它是一个「数值正确但结果出错」的误区 —— 而且不报错，容易陷入无法排查的死循环。**

这跟阶段 1 那个 `closed` / `filtered` 的 bug 是**同一个病**：
工具老老实实做了它该做的事，但**结果不反映事实**。

而且这次更隐蔽 —— **不是代码骗你，是你自己没检查输入。**

**可迁移的规则：**

> **用工具批量重放之前，先把「模板」读懂。**
> 模板里任何一个你不确定的字段，都会在 53 次（或 5 万次）重放里被放大同样的倍数。

---

## 5. 顺便：Burp 的 `Length` 列到底在算什么

**实测发现：`Length` 列不只是响应体长度。**

```text
密码 wrongpass → 响应头 328 + 响应体 4375 = 4703   ← 跟 Burp 显示的一致
密码 password  → 响应头 328 + 响应体 4413 = 4741
```

**所以 `Length` = 响应头 ＋ 响应体。**

**对比一下就更清楚：**

| 数字 | 从哪来 | 算的是什么 |
|---|---|---|
| `Content-Length: 4413` | 响应报文里的头字段 | **只有响应体** |
| `4741` | Burp 的 `Length` 列 | **响应头 + 响应体** |
| `328` | 两者之差 | 响应头的大小 |

> **为什么这个细节值得记：**
> 不同工具对同一个量的"度量口径"可能不同。
> 跟别人对数据时，先问一句「你这个长度算的是什么」，能省掉很多扯皮。

---

## 6. 根因

没有速率限制、账号锁定、验证码或者失败延迟。

**服务端一道防爆破的防线都没有**，导致攻击者可以对同一个账号**无限次**尝试 ——
而字典有 53 个候选，53 次请求几秒钟就跑完。

> 注意：**这不是"密码太弱"的问题** —— 那是受害者的责任。
> **根因在服务端：它没有限制「一个人能试多少次」。**

---

## 7. 修复方案

| 防线 | 挡住什么 | 有什么副作用／局限 |
|---|---|---|
| **速率限制** | 单一来源高频尝试 | **分布式爆破可以绕过**；**会误伤 NAT（例如校园网）的用户** |
| **账号锁定** | 针对某个账号的爆破 | **攻击者能反过来用它做拒绝服务**（故意冻结对方账号） |
| **失败延迟** | 拉低爆破速度 | **慢，但不会根治**；影响正常用户 |
| **验证码 / 多因素认证** | 自动化脚本 | 影响体验；验证码本身也可能被识别绕过 |

**另外：`login.php` 对「用户名不存在」和「密码错误」返回一样的页面 —— 这是对的。**

**如果两者返回不同的提示，攻击者就能先枚举出哪些用户名真实存在。**
这一步叫**用户名枚举（Username Enumeration）** —— 它把"盲猜"变成"有目标的爆破"，
**效率提高一个数量级。**

枚举的渠道不止登录页：注册页的「该用户名已被占用」、忘记密码页的反馈、
**响应时间差异**（查数据库 vs 直接返回）、**状态码或响应长度差异** —— 都是同一个洞。

> **所以「防用户名枚举」的要求是：所有失败路径返回一模一样的响应 ——
> 包括状态码、响应长度，甚至响应时间。**

---

## 8. 日志特征 ★

### 8.1 这次爆破在 access.log 里长什么样

```text
172.17.0.1 - - [23/Sep/2026:15:56:02 +0000] "GET /vulnerabilities/brute/?username=admin&password=batman&Login=Login HTTP/1.1" 200 1805 "http://127.0.0.1:8080/vulnerabilities/brute/?username=shit&password=fuckyou&Login=Login" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"
```

**⚠️ 注意这里的不寻常之处：** DVWA 的爆破模块用 **GET** 提交，所以密码进了日志。

**真实网站的登录表单几乎都用 POST** —— 那样的话密码在 body 里，
**access log 只记请求行和头，body 完全不记，日志里同样看不见密码。**

> 顺便：这条记录的 **Referer 里也带着一次密码**（`password=fuckyou`）——
> 那是上一次请求的完整 URL 被浏览器自动带过来的。
> **凭据放在 URL 里，会跟着跳转扩散到别的地方。**

### 8.2 我自己的检测工具能抓到吗

**第一次：抓不到。** 因为规则表里写的是常见 CMS 的登录路径：

```python
BRUTE_PATHS = ["/admin/login.php", "/wp-login.php", "/login", "/admin/"]
```

而 DVWA 的路径是 `/vulnerabilities/brute/` —— **一个都不匹配**。

**后来加了一条新规则 `[5]`，抓到了：**

```
[5] 凭据出现在 URL 中(查询串含 password= , >= 10 次)
    172.17.0.1          64 次
```

**这条规则为什么比"路径名匹配"好：**

因为路径名是**写死**的，换个地方就不适用了。而 `password` 出现次数的方法**泛用性高得多**。

**它不关心目标叫什么路径，只关心"有没有把密码放在 URL 上"。**
顺带还抓到了另一个问题：**把凭据放 URL 本身就是应用的设计缺陷**
（会被日志、浏览器历史、Referer、代理各记一遍）—— 一条规则同时覆盖两件事。

### 8.3 检测这类攻击的正确思路

考虑到目标可能使用 POST 或者 GET，**真正可靠的检测只能靠行为层的特征。**

| 层面 | 内容 | 日志里 |
|---|---|---|
| **行为层** | 谁、何时、打了哪个路径、**多少次** | ✅ **永远看得见**（GET / POST 都一样） |
| **内容层** | 密码是什么 | ⚠️ **只有 GET 才看得见** |

**「靠内容层检测」靠不住** —— 真实网站的登录表单用 POST，
**你没法要求目标"改用 GET 来让你检测"**。

**所以可靠的检测要基于「行为层」：同一个来源、短时间内、对同一个登录路径的大量尝试。**

**「内容层」只能算加分项**：有更好（能直接看到攻击者用了哪个字典），没有也能检测。

---

## 9. 遗留问题

- [ ] **Medium / High 档未打** —— High 档有失败延迟和 CSRF token
- [ ] **应该实际验证「用户名不存在」和「密码错误」是否真的返回一模一样**
      —— 目前只是读源码推断的（两者都走同一个 `else` 分支），**没有实测**
- [ ] 字典只有 53 条，不是真实规模的字典

---

## 附：环境噪声记录

| 现象 | 原因 | 影响 |
|---|---|---|
| 请求的 Cookie 里 `security` 出现两次：`security=low; PHPSESSID=...; security=medium` | 浏览器里同时存在两条同名 cookie；而 **PHP 解析 Cookie 时取第一个**（实测） | **页面提示的难度可能和实际生效的不一致** → 每次测试前看页面左下角的 `Security Level`，别靠记忆 |
| DVWA 的爆破模块用 **GET** 提交（真实网站用 POST） | 靶场为了教学方便 | **容易高估自己的检测能力** —— 在这个靶场里能看到密码，换成真实的 POST 站点就看不到了 |
| 日志里混着 UA 为 `python-requests/2.34.2` 的 87 条记录 | 调试环境/验证数据时跑的 Python 脚本 | 会被 `[3] 扫描器特征 UA` 规则报出来 —— **那不是攻击，是测试脚本**。分析日志时要能区分"自己的工具"和"目标的行为" |

---

## 附：这一篇和阶段 1 的关系

- `dirscan.py` 用的 `ThreadPoolExecutor` 和 Burp Intruder 是**同一件事** ——
  都是"把字典里的每一项，并发地打一遍，再从结果里挑出异常的"
- 区别只在于：`dirscan` 判断的是 HTTP 状态码，Intruder 判断的是**响应长度 / 关键词**
- **`loganalyze.py` 的 `[5]` 规则就是为这次攻击写的** —— 攻击方和检测方在我手里闭环
