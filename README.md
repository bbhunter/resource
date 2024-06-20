```bash
# automate-recon <target.com>
# automate-portscan <target.com>
> subdomain.out                   : Subdomain list               < $target
   > virtualhost.out              : Subdomain [vhost]            < subdomain.out 
   > ipresolv.out                 : IP resolved list             < subdomain.out
   > httpx-raws.out               : Probing + statuscode         < subdomain.out 
   > httpx.out                    : Subdomain live [80,443]      < httpx-raws.out 
   > openport.out                 : Active port scanning [full]  < cf-ipresolv.out
   > webstack.out                 : Hosting/Webstack             < subdomain.out   
   > ./raws/allurls               : Juicy crawling data          < subdomain.out
   > subdomain-hide.out           : Hidden subdomain from crawl  < ./raws/allurls

# automate-download <target.com>
   > ./juicy/listfiles               : List juicy files
   > ./juicy/download/*              : All js & other juicyfiles [json,toml,etc]

# Output = All Juicy Data + Generate Interest Pattern
< ./juicy/download/*.*
< ./raws/allurls
   > ./interest/variablefromjs       : Interest variable from js     < ./juicyfiles/download/js*
   > ./interest/querystrings-keys    : List querystrings + keys      < ./raws/allurls
   > ./interest/interesturi-allurls  : Interest path [/api,etc]      < ./raws/allurls
   > ./interest/interesturi-js       : Interest path [/api,etc]      < ./raws/data-gospider 
   > ./interest/paramsuniq           : Unique parameter list [live]  < ./raws/allurls
   > ./interest/passingparams        : Passing parameter list        < ./raws/allurls
   > ./interest/pathuri              : Extract Path only <brute>     < ./raws/allurls
   > ./interest/paramsuri            : Extract params only <brute>   < ./interest/paramsuniq
   > ./wordlist/parameter            : Generate params wordlist      < ./raws/allurls
   > ./wordlist/paths                : Generate paths wordlist       < ./raws/allurls * js
   > ./wordlist/js-variable          : Collecting var                < ./juicyfiles/download/js*
```

```bash
# automate-brute <target.com>
1. Juicy Path & Endpoint Bruteforce
   --> ./brute/internalpath     # /resource/wordlist/dir/internalpath.txt   <-- virtualhost.out
   --> ./brute/bigwordlist      # /resource/wordlist/dir/big-wordlist.txt   <-- ./interest/pathuri
   --> ./brute/sortwordlist     # /resource/wordlist/dir/short-wordlist.txt <-- ./interest/pathuri
   --> ./brute/springboot       # /resource/wordlist/dir/spring-boot.txt    <-- ./interest/pathuri

2. Parameter discovery (bruteforce)
   <-- ./interest/paramsuri
   --- ./brute/parameter1       # ./wordlist/parameter 
   --> ./brute/parameter2       # /resource/wordlist/parameter
```


# Vulnerable Testing
```bash
# automate-testing <target.com>
# automate-s3discovery <target.com>
# Automate Testing using Pattern
> vuln/nuclei-cvewebstack.out      : CVE Scanner by webstack      <
> ./fuzz/fuzz-fileinclusion       : gf fileinclusion pattern      < ./interest/paramsuniq
> ./fuzz/fuzz-openredirect        : gf redirect pattern           < ./interest/paramsuniq
> ./fuzz/fuzz-rce                 : gf rce pattern                < ./interest/paramsuniq
> ./fuzz/fuzz-idor                : gf idor pattern               < ./interest/paramsuniq
> ./fuzz/fuzz-sqli                : gf sqli pattern               < ./interest/paramsuniq
> ./fuzz/fuzz-ssrf                : gf ssrf pattern               < ./interest/paramsuniq
> ./fuzz/fuzz-ssti                : gf ssti pattern               < ./interest/paramsuniq
-----------------------------------------------------------------------------------------------------

1.  Hardcoded Sensitive Data Exposure -- Scanning download juicy files 
    <-- ./juicyfiles/download
    --> ./automationtesting/sensitivedata-generic
    --> ./automationtesting/sensitivedata
2.  S3 bucket discovery
    <-- ./raws/data-gospider + ./juicyfiles/*
    <-- /root/resource/wordlist/s3 :: ./wordlist/s3bucketnames
    --> ./automationtesting/s3bucket-all
    --> ./automationtesting/s3bucket-brute 
3.  Subdomain takeover
    <-- subdomain.out
    --> ./automationtesting/takeover-nxdomain
    --> ./automationtesting/takeover-subjack
4.  CVEs/Advisories
    <-- httpx.out
    --> ./automationtesting/RCE-Jolokia
    --> ./automationtesting/CVE-2020-5410       # Directory Traversal in Spring Cloud Config Server
    --> ./automationtesting/CVE-2018-1000129    # Jolokia XSS
5.  CORS Misconfig Scan 
    <-- httpx.out
    --> ./automationtesting/cors-vuln
6.  Unrestricted PUT method 
    <-- httpx.out
    --> ./automationtesting/unrestricted-putMethod
7.  Open Redirect > Clickjacking, XSS, SSRF
    <-- httpx.out
    --> ./automationtesting/openredirect-vuln
8.  XSS (Blind, Reflected)
    <-- ./raws/paramsuniq
    --> ./automationtesting/xss-reflected
9.  SSTI > RCE 
    <-- ./fuzz/fuzz-ssti
    --> ./automationtesting/ssti-vuln
10. SQLI Fuzzing (error based)
    <-- ./fuzz/fuzz-sqli
    --> ./automationtesting/sqli-vuln
11. File Inclusion
    <-- ./fuzz/fuzz-fileinclusion
    --> ./automationtesting/fileinclusion-vuln
12. HTTP Request Smuggling / Desync
    <-- httpx.out
    --> ./automationtesting/httpsmuggler-vuln
XX. Other 
    --> Command injection
    --> Host Header Injection (x-forwarded-host) > Open Redirect
    --> CRLF Injection > XSS, Cache-Poisoning
    --> Custom nuclei Pattern : New CVE&advisores, etc
    --> Dependencies vulnerability checking (SCA)
    --> SAST
```
