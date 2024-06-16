####################################################################################################################################
# automate-recon
# automate-portscan
# automate-dnsgen

automate-recon (){ 
OKGREEN='\033[92m'; RESET='\e[0m';

#---------------------------------------------------------------------------------------------------------------------------------#
# Enumerating subdomains + collecting urls
printf '%b\n\n\n'; echo -e "$OKGREEN Step1 : Subdomain Alteration & Permutation $RESET"
cd /root/sudomy; ./sudomy -d $1 --no-probe -o $1_sub; 
cd $1_sub/Sudomy-Output/$1; mkdir interest wordlist raws fuzz automationtesting juicyfiles; 
cat subdomain.txt | grep -F "$1" | tee subdomain.out; rm subdomain.txt;


#---------------------------------------------------------------------------------------------------------------------------------#
# Subdomain A,AAAA Resolving + IP resolved Cloudflare scan 
printf '%b\n\n\n'; echo -e "$OKGREEN Step2 : Subdomain A,AAAA,CNAME Resolving + IP resolved Cloudflare scan $RESET"

	# Subdomain A,AAAA,CNAME resolving
	cat subdomain.out | dnsprobe -r A -silent -t 500 | awk '{print $2" "$1}' | tee resolv1; 
	cat subdomain.out | dnsprobe -r AAAA -silent -t 500 | awk '{print $2" "$1}' | tee resolv2;
	cat subdomain.out | dnsprobe -r CNAME -silent -t 500 | awk '{print $2" "$1}' | tee resolv3;
	sort -u resolv1 resolv2 > ipresolv.out; sort -u resolv1 resolv2 resolv3 > ./raws/subdomain-resolved; rm resolv[1-3];

	# CloudFlare scan
	cat ipresolv.out | awk '{print $1}' | cf-check | sort -u | tee cf-ipresolv.out;


#---------------------------------------------------------------------------------------------------------------------------------#
# Subdomain HTTP Probing & Status Code Checking
printf '%b\n\n\n'; echo -e "$OKGREEN Step3 : Subdomain HTTP Probing [80,443] & Status Code Checking $RESET"
cat subdomain.out | httpx -vhost -status-code -content-length -web-server -title -threads 60 -timeout 5 | sort | \
awk '{print $2" "$3 " " $1" "$4$5$6$7$8$9$10$11$12$13}' | tee httpx-raws.out; cat httpx-raws.out | awk '{print $3}' | tee httpx.out; 


#---------------------------------------------------------------------------------------------------------------------------------#
# Virtualhost Discovery from subdomain list
printf '%b\n\n\n'; echo -e "$OKGREEN Step4 : Virtualhost Discovery from Subdomain list $RESET"
cat httpx-raws.out | grep vhost | awk '{print $3}' | tee virtualhost.out


#---------------------------------------------------------------------------------------------------------------------------------#
# Get urls from subdomain
printf '%b\n\n\n'; echo -e "$OKGREEN Step5 : URL Collecting from Passive Crawling $RESET"
cat subdomain.out | gau -retries 2 | tee ./raws/allurls-temp;


#---------------------------------------------------------------------------------------------------------------------------------#
# Collecting data (url,endpoint,js,etc) from active crawling
printf '%b\n\n\n'; echo -e "$OKGREEN Step6 : URL Collecting from Active Crawling $RESET"
gospider -d 1 --sitemap --robots -c 10 -t 10 -S httpx.out \
-H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:77.0) Gecko/20100101 Firefox/77.0" | \
tee tmp.txt; sort -u tmp.txt > ./raws/data-gospider; rm tmp.txt; 


#---------------------------------------------------------------------------------------------------------------------------------#
# Parsing & processing URL list (1)
printf '%b\n\n\n'; echo -e "$OKGREEN Step7 : Parsing & processing URL list (1) $RESET"
pattern1="(\?|\&)utm(_|-)(source|campaign|content|medium|term)=|\?fbclid=|\?gclid=|\?dclid=|\?mscklid=|\?zanpid=|\?gclsrc=|\?af_(ios|android)_url=|";
pattern2="\?af_force_deeplink=|\?af_banner=|\?af_web_dp=|\?is_retargeting=|\?af_(dp|esp)=|";
pattern3="pk_campaign=|piwik_campaign=|\_ga=|\?clickid=|\?Click|\?campaignid=|\?__cf_chl_(jschl|captcha)_tk__|";
pattern4="pagespeed=noscript|PageSpeed\%3Dnoscript|PageSpeed\%253Dnoscript|";
pattern5="\?_=|\,|\!|js\?vue";

# Data gau : Remove junk uri + probing
	egrep -v "${pattern1}${pattern2}${pattern3}${pattern4}${pattern5}" ./raws/allurls-temp | sort -u > tmp.txt; 
	cat tmp.txt | hakcheckurl -t 40 | awk '{print $2}' | tee ./raws/data-gau; 
	rm ./raws/allurls-temp tmp.txt;

# Data gospider : Parsing url + Remove junk uri 
	egrep "\[(url|form|robots|upload-form)\]" ./raws/data-gospider | awk '{print $5}' | \
	egrep -v "${pattern1}${pattern2}${pattern3}${pattern4}${pattern5}" | tee ./raws/data-gospider-url;

# Merger data data-gau + data-gospider-url
	sort -u ./raws/data-gospider-url ./raws/data-gau | egrep -v "${pattern1}${pattern2}${pattern3}${pattern4}${pattern5}" | \
	tee ./raws/allurls; rm ./raws/data-gospider-url;


#---------------------------------------------------------------------------------------------------------------------------------#
# Parsing & processing URL list (2) 
printf '%b\n\n\n'; echo -e "$OKGREEN Step8 : Parsing & processing URL list (2) $RESET"
ext1="\.(jpg|jpeg|png|doc|svg|pdf|ttf|eot|txt|cssx|css|gif|ico|woff|woff2|vue|js|json)|"
ext2="(eot|svg|ttf|woff|woff2|gif|css|ico|otf|ts|scss)\?"

passext1="\.(jpg|jpeg|png|doc|svg|pdf|ttf|eot|cssx|css|gif|ico|woff|woff2|js|json)|"
passext2="(eot|svg|ttf|woff|woff2|gif|css|txt|ico|otf|ts|scss)\?"
extjunk1="\.js\?ver=|\/wp\-json\/oembed|wp-content\/plugins|js\?\_|(eot|svg|ttf|woff|woff2|gif|css|ico)\?|node_module|jsessionid"

path1="\/(admin|api|auth|access|account|beta|board|bin|backup|cgi|create|checkout|debug|dashboard|deploy|dev|db|get|post|prod|pay|"
path2="purchase|panel|rest|user|member|internal|ticket|test|staging|sso|system|setting|server|staff|"
path3="java|jenkins|subscription|private|proxy|log|v[0-9]|[1-9]\.[0-9])"
junkpath1="\/wp-(json|content)\/"

junk1="\/svg|text\/(xml|html|plain|javascript|css)|";
junk2="(www\.youtube|\.google|player\.vimeo|pinterest|reddit|cdn-static-1\.medium|momentjs|googleadservices|fontawesome)\.com|";
junk3="application\/(x-www-form-urlencoded|json)|wp-(content|includes|json)|";
junk4="image\/(jpeg|png|tiff|gif)|audio\/(mpeg|mp3|mpa|mpa-robust|aac)|video\/(webm|mp4|3gp|mpeg|ogg|quicktime)|";
junk5="(africa|asia|america|australia|atlantic|europa|europe|pacific)\/|";
junk6="\/favicon\.ico|d\/(m|mm)\/y|m\/(d|dd)\/y|www\.w3\.org|google-analytics|pusher\.com|";
junk7="etc\/(gmt|utc)|";
junk8="node_modules)|";
junk9="zdassets\.com|datadoghq|googletagmanager\.com|unpkg\.com"


# Passing parameters ---> ./interest/passingparams
  grep "=" ./raws/allurls | egrep -i "${passext1}${passext2}" | egrep -v "${extjunk1}" | tee output1
  for i in $(cat output1); do URL="${i}"; LIST=(${URL//[=&]/=FUZZ&}); echo ${LIST} | awk -F '=' -vOFS='=' '{$NF="FUZZ"}1;' >> output2; done; 
  sort -u output2 | tee ./interest/passingparams; 

# Parameter list ---> ./interest/paramsuniq
  grep "=" ./raws/allurls | egrep -iv "${junk1}${ext1}${ext2}|\.htm" | tee output1; \
  for i in $(cat output1); do URL="${i}"; LIST=(${URL//[=&]/=FUZZ&}); echo ${LIST} | awk -F '=' -vOFS='=' '{$NF="FUZZ"}1;' >> output2; done; 
  sort -u output2 > output3; sed '/?/!d' output3 | tee output4; sort -u output4 ./interest/passingparams > ./interest/paramsuniq; rm output[0-9];

# Query Strings Parameter keys ---> ./interest/querystrings-keys
  cat ./raws/allurls | unfurl keypairs | sort -u | tee ./interest/querystrings-keys;

# Path > Brute
  cat raws/allurls | grep -v = | sed -e 's/\/[^\/]*$//' | sort -u | unfurl format %s://%d%p/ | tee ./interest/pathuri-temp
  sort -u httpx.out ./interest/pathuri-temp >> ./interest/pathuri; rm ./interest/pathuri-temp;

# Param > Brute
  cat interest/paramsuniq | cut -d"?" -f1 | sort -u | tee ./interest/paramsuri
  sed -i 's/$/?FUZZ/' ./interest/paramsuri

# Interest URI < ./raws/allurls
  egrep -v '${junkpath1}' ./raws/allurls | egrep "${path1}${path2}${path3}" | sort -u > ./interest/interesturi-allurls 

# Parse Interest URI, endpoint from [linfinder] < ./raws/data-gospider
  egrep "\[linkfinder\]" ./raws/data-gospider | awk '{print $4" "$6}' | \
  egrep -v "${junk1}${junk2}${junk3}${junk4}${junk5}${junk6}${junk7}${junk8}${junk9}" | sort -u | tee ./interest/interesturi-js ;


#---------------------------------------------------------------------------------------------------------------------------------#
# Colecting Juicy file 
printf '%b\n\n\n'; echo -e "$OKGREEN Step9 : Collect interesting parameter + filter query strings parameter $RESET"
filterpath="(\/cdn|wp-(content|admin|includes)\/|\?ver=|\/recaptcha|wwww\.google)|"
filter1="s3Capcha|wow\.min|jasny-bootstrap|jasny-bootstrap\.min|node_modules|";
filter2="jquery|ravenjs|static\.freshdev|"
filter3="wpgroho|polyfill\.min|bootstrap|";
filter4="myslider|modernizr|modernizr\.(min|custom)|hip";	

# Step 1
  # Javascript files : 1) Fetch js file + 2) Crawling JS files from given urls/subdomains
	# Collecting js file (1)
	egrep "\.js" ./raws/data-gau | hakcheckurl -t 40 | grep "200" | awk '{print $2}' | tee gau-js-temp; 
	egrep "\[javascript\]" ./raws/data-gospider | awk '{print $3}' | tee gospider-js-temp;

	# Other juicy files :: json, txt, toml, xml, yaml, etc : 1) Fetch other juicy file + 2) Crawling other juicy files 
	otherext="\.json|\.txt|\.yaml|\.toml|\.xml|\.config|\.tar|\.gz|\.log"
	egrep "${otherext}" ./raws/data-gau | hakcheckurl -t 40 | grep "200" | awk '{print $2}' | tee gau-other-temp; 
	egrep "\[url\]" ./raws/data-gospider | egrep "${otherext}" | awk '{print $5}' | tee gospider-other-temp;

		sort -u gau-js-temp gospider-js-temp > ./juicyfiles/allJSfiles-temp1;
		sort -u gau-other-temp gospider-other-temp > ./juicyfiles/otherfiles;

	# Delete junk js -- awk -F / '{print $NF}'
	cat ./juicyfiles/allJSfiles-temp1 | grep "\.js" | cut -d"?" -f1 | egrep -v "${filterpath}${filter1}${filter2}${filter3}${filter4}" | \
	sort -u | tee ./juicyfiles/jsfiles

rm gau-other-temp gospider-other-temp gospider-js-temp gau-js-temp;


#---------------------------------------------------------------------------------------------------------------------------------#
# Fetch travis build log
printf '%b\n\n\n'; echo -e "$OKGREEN Step10 : Fetch Travis Build Log $RESET"
echo $1 | cut -d"." -f1 | tee temp; for org in $(cat temp); do echo "$org"; done
rm temp; cd ./juicyfiles; secretz -c 10 -t $org; mv output/ travislog; cd ../;


#---------------------------------------------------------------------------------------------------------------------------------#
# Generate Wordlist
printf '%b\n\n\n'; echo -e "$OKGREEN Step11 : Generate Wordlist (Parameter & Path) $RESET"

# Parameter  
  cat ./raws/allurls | unfurl keys | tee ./wordlist/parameter-temp
  cat ./wordlist/parameter-temp | egrep -ve "\%|\." -ve "[a-zA-Z]{20,30}" | tr -d ':' | sort -u > ./wordlist/parameter; rm ./wordlist/parameter-temp;

# Path
  fil1="wp-(content|includes|json)|"
  fil2="(docs|drive)\.google|\%22|amp|sha(256|384|512)"
  cat ./interest/pathuri | egrep -v "=|${fil1}${fil2}${ext1}${ext2}" | unfurl path | sed 's#/#\n#g' | sort -u | egrep -v "[a-zA-Z]{20,40}" | tee ./wordlist/paths


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
# Webanalyze
printf '%b\n\n\n'; echo -e "$OKGREEN Step13 : Uncovers technologies from Subdomain list $RESET"
webanalyze -apps /root/resource/src/apps.json -worker 10 -hosts httpx.out -output csv | tee webanalyzes.out;


#---------------------------------------------------------------------------------------------------------------------------------#
# Taking screenshots
printf '%b\n\n\n'; echo -e "$OKGREEN Step15 : Taking screenshots $RESET"
mkdir screens; 
gowitness file --source subdomain.out -d ./screens;
gowitness report generate; mv report-0.html gowitness.html;


#---------------------------------------------------------------------------------------------------------------------------------#
# Copying recon result
cp -r /root/sudomy/$1_sub/Sudomy-Output/$1 /var/www/html/automate/$1
zip -r /var/www/html/automate/$1.zip /root/sudomy/$1_sub/Sudomy-Output/$1

# Slack alert 
curl -X POST -H 'Content-type: application/json' --data '{"text":"Automate Recon Done :)"}' \
https://hooks.slack.com/services/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
#---------------------------------------------------------------------------------------------------------------------------------#

}



####################################################################################################################################
automate-dnsgen(){
# Subdomain Alteration & Permutation
printf '%b\n\n\n'; echo -e "$OKGREEN Subdomain Alteration & Permutation $RESET"
cd /root/sudomy/$1_sub/Sudomy-Output/$1
cat subdomain.out | dnsgen - | tee dnsgen-temp; sort -u subdomain.out dnsgen-temp > dnsgen; 
cat dnsgen | dnsprobe -r A -silent -t 500 | tee dnsgen-A
cat dnsgen | dnsprobe -r AAAA -silent -t 500 | tee dnsgen-AAAA
cat dnsgen | dnsprobe -r CNAME -silent -t 500 | tee dnsgen-CNAME
cat dnsgen-A dnsgen-AAAA dnsgen-CNAME | awk '{print $1}' | sort -u >> dnsgen-temp.out;
awk 'FNR==NR {a[$0]++; next} !($0 in a)' subdomain.out dnsgen-temp.out | tee dnsgen.out
rm dnsgen dnsgen-temp dnsgen-A dnsgen-AAAA dnsgen-CNAME dnsgen-temp.out;

#---------------------------------------------------------------------------------------------------------------------------------#
# Copying recon result
rm -rf /var/www/html/automate/$1 /var/www/html/automate/$1.zip
cp -r /root/sudomy/$1_sub/Sudomy-Output/$1 /var/www/html/automate/$1
zip -r /var/www/html/automate/$1.zip /root/sudomy/$1_sub/Sudomy-Output/$1

curl -X POST -H 'Content-type: application/json' --data '{"text":"Automate Subdomain Alteration & Permutation Done :)"}' \
https://hooks.slack.com/services/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
}



####################################################################################################################################
automate-portscan(){
printf '%b\n\n\n'; echo -e "$OKGREEN Active Port Scanning $RESET"
cd /root/sudomy/$1_sub/Sudomy-Output/$1

# Port scan subdomains
printf '%b\n\n\n'; echo -e "$OKGREEN Step1.1 : Subdomain Port Scan Common Port $RESET"	
cat raws/subdomain-resolved | awk '{print $2}' | sort -u | httpx -vhost -threads 30 -silent -ports 4443,8000-8099,8880,8888,8443,9200 | \
tee httpx-9999.out; rm temp temp2 resolv[0-9];

# Port scan ip 
printf '%b\n\n\n'; echo -e "$OKGREEN Step1.2 : IP lis Port Scan Full Port $RESET"
naabu -t 10 -hL cf-ipresolv.out -ports full -exclude-ports 1-200 -retries 3 | tee openport.out;

#---------------------------------------------------------------------------------------------------------------------------------#
# Copying result
rm -rf /var/www/html/automate/$1 /var/www/html/automate/$1.zip
cp -r /root/sudomy/$1_sub/Sudomy-Output/$1 /var/www/html/automate/$1
zip -r /var/www/html/automate/$1.zip /root/sudomy/$1_sub/Sudomy-Output/$1
curl -X POST -H 'Content-type: application/json' --data '{"text":"Automate Port Scanning Done :)"}' \
https://hooks.slack.com/services/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
}






