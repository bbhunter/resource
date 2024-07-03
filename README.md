```sh
1. automate-recon <target.com>
   > subdomain.out            : Subdomain list                   
   > virtualhost.out          : Subdomain [vhost]                  < subdomain.out 
   > ipresolv.out             : IP resolved list                   < subdomain.out
   > httpx-raws.out           : Probing + statuscode               < subdomain.out 
   > httpx.out                : Subdomain live [80,443]            < httpx-raws.out 
   > webstack.out             : Hosting/Webstack                   < subdomain.out   
   > /raws/allurls            : Juicy crawling data                < subdomain.out
      > subdomain-hide.out        : Hidden subdomain from crawl    < /raws/allurls
      > /raws/path-uri            : Extract Path only <brute>      < /raws/allurls
      > /raws/path-interest       : Extract Path Interest          < /raws/allurls
      > /raws/listfiles           : List juicy files               < /raws/allurls
         > /raws/download/*       : Downloaded /raws/listfiles     < /raws/listfiles 
            > /raws/download-path      : Extract Path from Files   < /raws/download/*
            > /raws/download-url       : Extract URLs from Files   < /raws/download/*


2. automate-portscan <target.com>
   > port-ipresolv.out            : Active port scanning from IP Address 
   > port-subdomain.out           : Active port scanning from Subdomain

```


### Disclosure & Fuzzing
```sh
Basic Testing
> CVE Advisories based on Webstack
   > vuln/nuclei-cvewebstack-subdomain.out
   > vuln/nuclei-cvewebstack-ipresolv.out
> Subdomain Takeover
> Discovery Sensitive Data Exposure
   > Downloaded Files
   > Other url (github, bucket)
> S3 Bucket Discovery (Soon)

Fuzzing
> SS
```
