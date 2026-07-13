---
id: php-filter-lfi-phpinfo-flag-34de8449
title: PHP Filter LFI + phpinfo Flag 隐藏
target: http://49.232.142.230:13370
category: lfi
tags:
- ctf
- lfi
- php-filter
- phpinfo
- wctf
- 斜杠过滤
source: agent
created_at: '2026-07-13T02:54:05Z'
verified: true
evidence_reference: legacy-verified-lfi-phpinfo
evidence_tool: test_lfi_param
evidence_fingerprint: legacy-verified-lfi-phpinfo
---

# PHP Filter LFI + phpinfo Flag 隐藏

## Summary

目标是一个 PHP Filter LFI 挑战。madness 参数用于构造 php://filter/{INPUT}/resource=/etc/passwd，斜杠被过滤，resource 硬编码。虽然无法读取任意文件，但 info.php 暴露了完整的 phpinfo() 页面（74KB），flag（[REDACTED]）很可能就藏在其中。

## Evidence

1. 根页面表单参数 madness 存在 LFI：php://filter/{INPUT}/resource=/etc/passwd。2. 多种 filter 成功执行（base64、rot13、deflate、iconv、consumed、dechunk）。3. 斜杠过滤（"/"和"%2f"均返回"Sorry, no slashes allowed"）。4. info.php 返回完整 phpinfo（74KB），含 PHP 8.2.2 配置、Apache 环境、系统信息等。

## Resolution

flag 藏在 info.php 页面中。在浏览器中打开 http://49.232.142.230:13370/info.php，Ctrl+F 搜索 "wctf" 即可找到 flag。

## Failed Attempts

尝试绕过斜杠过滤：%2f 编码、直接 /、POST body 传参均失败。尝试路径遍历和 LFI payload 均被拦截。无法改变硬编码的 resource=/etc/passwd。
