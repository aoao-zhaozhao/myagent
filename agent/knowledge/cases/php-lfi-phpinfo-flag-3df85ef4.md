---
id: php-lfi-phpinfo-flag-3df85ef4
title: PHP LFI + phpinfo() 环境变量泄露 flag
target: http://49.232.142.230:10122
category: recon
tags:
- CTF
- phpinfo
- 信息泄露
- 环境变量
source: agent
created_at: '2026-07-13T03:42:48Z'
verified: true
evidence_reference: legacy-verified-recon-phpinfo
evidence_tool: search_http_body
evidence_fingerprint: legacy-verified-recon-phpinfo
---

# PHP LFI + phpinfo() 环境变量泄露 flag

## Summary

目标是一个 PHP 8.2.2 应用，提供 madness 参数进行 PHP filter LFI（php://filter//resource=），同时具备 phpinfo() 页面。在 phpinfo() 中，环境变量 FLAG 和 $_ENV['FLAG'] 直接暴露了 flag 内容：[REDACTED]

## Evidence

1. 主页（/）提供 madness 参数，可执行 PHP filter 读取任意文件（如 /etc/passwd）
2. 存在 /info.php 页面，为 PHP 8.2.2 的 phpinfo() 完整输出（~74KB）
3. 在 info.php 的 $_ENV['FLAG'] 和 Apache FLAG 环境变量中直接泄露 flag
4. 使用 search_http_body(url=info.php, keyword=wctf) 确认命中 2 次

## Resolution

访问 /info.php 页面，搜索关键词 "wctf" 或查看环境变量（Environment）部分的 FLAG 条目即可获取 flag。

## Failed Attempts

未涉及复杂的漏洞利用，直接通过 phpinfo() 页面信息收集即可发现 flag。
