# web-security-lab

> DVWA 靶场漏洞复现笔记 —— **每一篇都含「根因 / 修复方案 / 日志特征」三栏**
> 配套仓库：[security-lab](https://github.com/yizi2333/security-lab)（自己写的安全工具）

---

## 这个仓库是关于什么的

<!-- ★ 2–4 句，用你自己的话说。可以想想这三个问题：
     ① 为什么要建这个仓库？（不是"为了学习"，那太笼统 —— 你当初为什么决定要动手复现？）
     ② 怎么练的？（不看别人的 writeup 先自己打？还是打了再对照？）
     ③ 跟 security-lab 那个仓库什么关系？
-->

（待填 ★）

---

## Writeup 索引

| # | 模块 | 难度 | 一句话关键结论 | 行数 | 报文 |
|---|---|---|---|---|---|
| **01** | [Brute Force](writeups/01-bruteforce/) | Low | 爆破的前提是**先找到能可靠区分"成功/失败"的判据** —— 而判据没有通用答案，每个应用都要重新找 | 424 | 5 份 |
| **02** | [Command Injection](writeups/02-command-injection/) | Low · Medium | 用户输入从「**数据**」变成了「**命令语法**」 | 647 | 4 份 |
| **03** | [SQL Injection](writeups/03-sql-injection/) | Low | 同样是"数据变成语法"，但这次的杠杆是**一对单引号** | 555 | 2 份 |
| **04** | [XSS](writeups/04-xss/)（反射 / 存储 / DOM） | Low | 三种的区别只有一个问题：**那段 HTML 字符串，是在哪里被拼出来的** | 1001 | 6 份 |

**合计 2627 行**，17 份原始报文（全部是真实抓包，存在各自的 `raw/`）

---

## 每篇的统一结构

```text
0  一句话总结              1  环境
2  漏洞原理                 （贴源码 + 找出"原罪行"是哪一行）
3  复现                     （附 raw/ 里的原始报文）
4  重点专题 ★               （这一关最核心的那个概念）
5  从 PoC 到真实危害 ★      （"弹个窗有什么用"这类追问）
6  根因                     （写机制，不写"没过滤特殊字符"）
7  修复方案                 （错误做法 / 正确做法 / 修在哪一层）
8  日志特征 ★               （这一发攻击在 access.log 里长什么样）
9  遗留问题
附 环境噪声记录             （差点让我误判的东西）
```

**为什么每篇都有「日志特征」这一节：**
因为它要喂给另一个仓库的 `loganalyze.py` —— 把「打靶场」和「写检测工具」接成一个闭环：
**自己打的攻击，自己写的工具能不能抓到？**（其中就有一次抓不到，见下面第 5 条）

---

## ★ 我踩过的 8 个「静默失效」

> 这一类 bug 的共同点：**不报错、不崩溃、不提示 —— 但给你一个错误的结果。**

| # | 假象（我以为的） | 真相（实际是） | 出自 |
|---|---|---|---|
| 1 | 端口显示 `closed` | 其实是 **`filtered`** —— 本机回环对未监听端口是**丢包**不是拒绝，超时被当成了"关闭" | 阶段 1 · 端口扫描器 |
| 2 | Burp Intruder 跑了 53 行 | 53 行全是**废数据**（payload 根本没被替换进去） | 01 Brute Force |
| 3 | `py_compile` 报语法错 | 是**沙箱**不许写 `__pycache__`，代码本身没问题 | 阶段 1 |
| 4 | 关键字"搜不到" | `[regex]::Escape` 和 `-SimpleMatch` 一起用 → 实际搜的是**转义后的字面量** | 阶段 1 |
| 5 | 日志里"没有 SQL 注入" | `SQLI_KEYWORDS` 写的是**大写**，比对前却调了 `.lower()` → 规则**恒不命中** | 03 SQL Injection |
| 6 | 文件"坏了"，722 行读成 613 行 | PowerShell 默认用 **GBK** 去读 UTF-8 文件 —— 文件完好，是**读的工具**错了 | 04 XSS |
| 7 | 刚填好的内容"自己消失了" | VS Code 里是打开时的**旧内存副本**，保存时**整份覆盖**了磁盘上的新内容 | 04 XSS |
| 8 | 检测规则"没命中" | 特征串**拼错了一个字母**（`javascrpt`）—— 而且它是在"讲假阴性"的那一节里写错的 | 04 XSS |

<!-- ★ 一句总结（这是 README 里最值钱的一句，面试会问）
     提示：这 8 个的共同结构是什么？
           "我看到的" 和 "事实" 之间，隔了一层什么？
     再想：这对做安全分析/取证意味着什么？ -->

**★ 这 8 个坑教给我的共同教训是：** （待填 ★）

---

## 环境

| 项 | 值 |
|---|---|
| 靶场 | DVWA v1.10 *Development*（Docker 镜像 `vulnerables/web-dvwa`） |
| 服务端 | Apache 2.4.25 (Debian) ／ PHP 7.0.30 ／ MariaDB |
| 代理 | Burp Suite Community v2026.8（监听 `127.0.0.1:8081`，避开 DVWA 的 8080） |
| 客户端 | Chrome 151（Windows） |
| **网络约束** | **一律绑 `127.0.0.1`，绝不绑 `0.0.0.0`** —— 校园网里 `0.0.0.0` 等于把靶场开成公网后门 |

**难度怎么切**：DVWA 的难度是**一个客户端 cookie**（`security=low|medium|high|impossible`），
不是服务端配置 —— 所以 Burp 里改一行 cookie 就能切档。

---

## 目录

```text
writeups/
  01-bruteforce/          README.md  +  raw/（原始报文）
  02-command-injection/   README.md  +  raw/
  03-sql-injection/       README.md  +  raw/
  04-xss/                 README.md  +  _证据台账.md  +  raw/
logs/
  dvwa-access.log         从靶场容器导出的 access.log（喂给 loganalyze.py 练手）
wordlists/
  passwords.txt           53 条弱口令字典
for_ask/                  我自己攒的问题清单（问到答案就补在同一个文件里）
```

---

## 模块进度

| 模块 | Low | Medium | High |
|---|---|---|---|
| Brute Force | ✅ | ⬜ | ⬜ |
| Command Injection | ✅ | ✅ | ⬜ |
| CSRF | ⬜ | ⬜ | ⬜ |
| File Inclusion | ⬜ | ⬜ | ⬜ |
| File Upload | ⬜ | ⬜ | ⬜ |
| Insecure CAPTCHA | ⬜ | ⬜ | ⬜ |
| SQL Injection | ✅ | ⬜ | ⬜ |
| SQL Injection (Blind) | ⬜ | ⬜ | ⬜ |
| Weak Session IDs | ⬜ | ⬜ | ⬜ |
| XSS (DOM) | ✅ | ⬜ | ⬜ |
| XSS (Reflected) | ✅ | ⬜ | ⬜ |
| XSS (Stored) | ✅ | ⬜ | ⬜ |
| CSP Bypass | ⬜ | ⬜ | ⬜ |
| JavaScript | ⬜ | ⬜ | ⬜ |

**Low 档 6 / 14** ｜ 含 Medium 共 7 项 ｜ writeup 4 篇 / 2627 行

---

## 相关仓库

- **[security-lab](https://github.com/yizi2333/security-lab)** —— 三个自写的安全工具：
  端口扫描器（三态区分 open/closed/filtered）、目录扫描器、日志分析器（含 6 条可疑行为检测规则）

---

## 免责声明

**所有测试都在本机的 Docker 靶场（DVWA）中完成，仅用于学习。**
没有对任何未授权的真实系统发起过测试。

---

<!-- ★ 最后可选：写一句"接下来要做什么"（CSRF / File Upload / SQLi Blind…），
     让仓库看起来是活的、在推进的。想写就写，不想写就删掉这一行注释。 -->
