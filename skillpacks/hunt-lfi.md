---
name: hunt-lfi
description: "Hunt LFI/RFI/Path Traversal — /etc/passwd read, log poisoning to RCE, PHP filter-chain RCE, php:///data:///zip:///phar:// wrappers, RFI via allow_url_include, traversal read/write/delete."
extensions: php, phtml, inc, php5
---

# HUNT-LFI — key sinks & severity for STATIC review

## Sinks to flag (user input reaching a file/include operation)
- include / include_once / require / require_once with $_GET/$_POST/$_REQUEST/$_COOKIE
- file_get_contents / fopen / readfile / file / fpassthru on user-controlled path
- Any of the above accepting a php:// / data:// / phar:// / zip:// / expect:// wrapper

## Severity rubric
- php://filter read reachable -> UPGRADEABLE to RCE via iconv filter-chain (Synacktiv 2022) => CRITICAL
- include of remote URL when allow_url_include=On (RFI) => CRITICAL
- file read exposing .env / wp-config.php / config.php / private keys / cloud creds => HIGH
- non-sensitive file read only => MEDIUM

## Attack-path notes to include in findings
- Show the traversal/wrapper payload (../../etc/passwd, php://filter/convert.base64-encode/resource=..)
- State whether the sink appends a fixed base dir or extension (affects exploitability)
- For php:// filter reads, note the filter-chain RCE upgrade explicitly.

## False-positive discipline
- A path echoed in an error is NOT proof; only real file CONTENTS or executed code confirm.
- If input is validated against an allowlist or basename()-only, downgrade/confidence Low.
