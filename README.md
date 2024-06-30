
### Recon
```sh
> subdomain.out                 : Subdomain list                   
   > virtualhost.out              : Subdomain [vhost]               < subdomain.out 
   > ipresolv.out                 : IP resolved list                < subdomain.out
   > httpx-raws.out               : Probing + statuscode            < subdomain.out 
   > httpx.out                    : Subdomain live [80,443]         < httpx-raws.out 
   > webstack.out                 : Hosting/Webstack                < subdomain.out   
   > ./raws/allurls               : Juicy crawling data             < subdomain.out
      > subdomain-hide.out           : Hidden subdomain from crawl  < ./raws/allurls
      > ./interest/pathuri           : Extract Path only <brute>    < ./raws/allurls

# automate-download <target.com>
   > ./juicy/listfiles            : List juicy files
   > ./juicy/download/*           : All js & other juicyfiles [json,toml,etc]

# automate-portscan <target.com>
   > port-ipresolv.out            : Active port scanning from IP Address 
   > port-subdomain.out           : Active port scanning from Subdomain
```

### Bruteforce
```sh
1. Juicy Path & Endpoint Bruteforce
   --> ./brute/internalpath     # /resource/wordlist/dir/internalpath.txt   <-- virtualhost.out
   --> ./brute/bigwordlist      # /resource/wordlist/dir/big-wordlist.txt   <-- ./interest/pathuri
   --> ./brute/sortwordlist     # /resource/wordlist/dir/short-wordlist.txt <-- ./interest/pathuri
```


### Disclosure & Fuzzing
```sh
1. CVE Advisories based on Webstack
2. Subdomain Takeover
3. Discovery Sensitive Data Exposure
   - Downloaded Files
   - Other url (github, bucket)
4. Discovery Interest Path
5. S3 Bucket Discovery (Soon)

# automate-fuzz
```
