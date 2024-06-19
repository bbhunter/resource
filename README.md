# Focus on Information Disclosure
## Reconnaissance & Collecting Juicy Data 
```bash
# automate-recon <target.com>
# automate-portscan <target.com>
------------------------------------------------------------------------------------------------
> subdomain.out                   : Subdomain list               < $target
   > virtualhost.out              : Subdomain [vhost]            < subdomain.out 
   > ipresolv.out                 : IP resolved list             < subdomain.out
   > httpx-raws.out               : Probing + statuscode         < subdomain.out 
   > httpx.out                    : Subdomain live [80,443]      < httpx-raws.out 
   > httpx-9999.out               : Subdomain live [8000-9999]   < unique httpx.out::subdomain.out
   > openport.out                 : Active port scanning [full]  < cf-ipresolv.out
   > webstack-cname.out           : Hosting/Webstack [cname]     < subdomain.out   
   > webstack-analyzes.out        : Webanalyzer scan             < httpx.out
   > ./raws/allurls               : Juicy crawling data          < subdomain.out
   > subdomain-hide.out           : Hidden subdomain from crawl  < ./raws/allurls

# automate-download <target.com>
------------------------------------------------------------------------------------------------
> ./juicy/listfiles               : List juicy files
> ./juicy/download/*              : All js & other juicyfiles [json,toml,etc]


# Output = All Juicy Data + Generate Interest Pattern
------------------------------------------------------------------------------------------------
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


## Parameter & Path Discovery (Brute)
```bash
# automate-brute <target.com>
------------------------------------------------------------------------------------------------
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
------------------------------------------------------------------------------------------------
> ./fuzz/fuzz-fileinclusion       : gf fileinclusion pattern      < ./interest/paramsuniq
> ./fuzz/fuzz-openredirect        : gf redirect pattern           < ./interest/paramsuniq
> ./fuzz/fuzz-rce                 : gf rce pattern                < ./interest/paramsuniq
> ./fuzz/fuzz-idor                : gf idor pattern               < ./interest/paramsuniq
> ./fuzz/fuzz-sqli                : gf sqli pattern               < ./interest/paramsuniq
> ./fuzz/fuzz-ssrf                : gf ssrf pattern               < ./interest/paramsuniq
> ./fuzz/fuzz-ssti                : gf ssti pattern               < ./interest/paramsuniq
------------------------------------------------------------------------------------------------
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



# Hardcoded/Sensitive Data Regex Pattern
| Platform              | Key Type              | Regular Expression                                                           |
|-----------------------|--------------------   |----------------------------------------------------------------------------  |
| ***Generic credential***    | Password, Token, etc  | "[0-9a-zA-Z*-_/]{20,80}"                                               |
| Private Key           | RSA, DSA, EC, PGP     | "---(BEGIN|END)"                                                             |
| Amazon MWS            | Auth Token            | "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"  |
| AWS                   | Access Key ID         | "AKIA[0-9A-Z]{16}"                                                           |
|                       | Secret Access Key     | ***(Generic Credential)*** "[0-9a-zA-Z*-_/+]{20,80}"                         |
| Bitly                 | OAuth Access Token    | ***(Generic Credential)***                                                   |
| CircleCI              | Access Token          | ***(Generic Credential)*** "[0-9a-f]{40}"                                    |
| Facebook              | OAuth Access Token    | ***(Generic Credential)*** "[A-Za-z0-9]{125}"                                |
| Gitlab                | Auth Token            | ***(Generic Credential)***                                                   |
| Github                | OAuth Access Token    | ***(Generic Credential)*** "[0-9a-zA-Z]{35,40}"                              |
| Google                | API Key               | "AIza[0-9A-Za-z*]{35}"                                                       |
|                       | OAuth Access Token    | "ya29\\.[0-9A-Za-z*]+"                                                       |
| Instagram             | OAuth Access Token    | "[0-9a-fA-F]{7}\\.[0-9a-fA-F]{32}"                                           |
| MailChimp             | API Key               | "[0-9a-f]{32}-us[0-9]{1,2}"                                                  |
| Mailgun               | API Key               | "key-[0-9a-zA-Z]{32}"                                                        |
| NPM                   | Auth Token            | "[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}"               |
| PayPal Braintree      | OAuth Access Token    | "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}"                    |
| Picatic               | API Key               | "sk_live_[0-9a-z]{32}"                                                       |
| Slack                 | OAuth Access Token    | "key-[0-9a-zA-Z]{32}"                                                        |
| SendGird              | API Key               | "SG\\.[a-zA-Z0-9]{22}\\.[a-zA-Z0-9*-_]{43}"                                  |
| Stripe                | API Key               | "sk_live_[0-9a-zA-Z]{24}"                                                    |
|                       | Restricted API Key    | "rk_live_[0-9a-zA-Z]{24}"                                                    |
| Square                | Access Token          | "sq0atp-[0-9A-Za-z*]{22}"                                                    |
|                       | OAuth Secret          | "sq0csp-[0-9A-Za-z*]{43}"                                                    |
| Twilio                | Account/App SID       | "(AC|AP)[a-zA-Z0-9]{32}"                                                     |
|                       | API Key SID           | "SK[0-9a-fA-F]{32}"                                                          |
| Travis CI             | Auth Token            | ***(Generic Credential)***                                                   |



```bash
Todo
# Firebase Custom Token and API key
# Google Cloud Messaging Key
# Hubspot API key
# Dropbox API Bearer/Auth Token
# Microsoft Azure Client ID, secret & Tenant ID
# Mapbox API key 
# Jumpcloud API key
# Salesforce API Key/Bearer Token 
# WPEngine API key & Account Name
# DataDog API Key & Application Key
# Gitlab Personal/Private Token
# Paypal ClientID & Secret
```
