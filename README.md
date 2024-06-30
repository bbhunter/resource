```bash
# automate-recon <target.com>
> subdomain.out                   : Subdomain list               < $target
   > virtualhost.out              : Subdomain [vhost]            < subdomain.out 
   > ipresolv.out                 : IP resolved list             < subdomain.out
   > httpx-raws.out               : Probing + statuscode         < subdomain.out 
   > httpx.out                    : Subdomain live [80,443]      < httpx-raws.out 
   > webstack.out                 : Hosting/Webstack             < subdomain.out   
   > ./raws/allurls               : Juicy crawling data          < subdomain.out
   > subdomain-hide.out           : Hidden subdomain from crawl  < ./raws/allurls

# automate-download <target.com>
   > ./juicy/listfiles               : List juicy files
   > ./juicy/download/*              : All js & other juicyfiles [json,toml,etc]

   # Output = All Juicy Data + Generate Interest Pattern
   > ./interest/variablefromjs       : Interest variable from js     < ./juicyfiles/download/js*
   > ./interest/querystrings-keys    : List querystrings + keys      < ./raws/allurls
   > ./interest/interesturi-js       : Interest path [/api,etc]      < ./raws/data-gospider 
   > ./interest/paramsuniq           : Unique parameter list [live]  < ./raws/allurls
   > ./interest/passingparams        : Passing parameter list        < ./raws/allurls
   > ./interest/pathuri              : Extract Path only <brute>     < ./raws/allurls
   > ./interest/paramsuri            : Extract params only <brute>   < ./interest/paramsuniq
   > ./wordlist/parameter            : Generate params wordlist      < ./raws/allurls
   > ./wordlist/paths                : Generate paths wordlist       < ./raws/allurls * js
   > ./wordlist/js-variable          : Collecting var                < ./juicyfiles/download/js*

# automate-portscan <target.com>
   > openport.out                 : Active port scanning [full]  < cf-ipresolv.out
   > openport.out                 : Active port scanning [full]  < cf-ipresolv.out
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


```bash
# automate-disclosure
1. CVE Advisories based on Webstack
2. Subdomain Takeover
3. Discovery Sensitive Data Exposure
   - Downloaded Files
   - Other url (github, bucket)
4. Discovery Interest Path
5. S3 Bucket Discovery (Soon)


# automate-fuzz

```
