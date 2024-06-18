
OKGREEN='\033[1;33m'; RESET='\e[0m';
export GOROOT=/usr/lib/go
export GOPATH=$HOME/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH

#---------------------------------------------------------------------------------------------------------------------------------#
# Enumerating subdomains + collecting urls (Tool : sudomy)
echo -e "$OKGREEN Subdomain Alteration & Permutation $RESET"
cd /home/Sudomy; ./sudomy -d $1 --no-probe -o $1; 
cd $1/Sudomy-Output/$1; mkdir interest wordlist raws fuzz automationtesting juicy webstack; 
sudo mv subdomain.txt subdomain.out;


#---------------------------------------------------------------------------------------------------------------------------------#
# Subdomain A,AAAA Resolving + IP resolved Cloudflare scan  (dnsx + cf-check)
printf '%b\n\n\n'; echo -e "$OKGREEN Step2 : Subdomain A,AAAA Resolving $RESET"

	# Subdomain A,AAAA,CNAME resolving
	cat subdomain.out | dnsx -silent -a -resp-only | sudo tee resolv1; 
	cat subdomain.out | dnsx -silent -aaaa -resp-only | sudo tee resolv2;
	sort -u resolv1 resolv2 | sudo tee ipresolv.out; sudo rm resolv[1-2];


#---------------------------------------------------------------------------------------------------------------------------------#
# Subdomain HTTP Probing & Status Code Checking
printf '%b\n\n\n'; echo -e "$OKGREEN Step3 : Subdomain HTTP Probing [80,443] & Status Code Checking $RESET";
sudo /home/tool/httpx -vhost -status-code -content-length -web-server -title -threads 60 -timeout 5 -l subdomain.out | sort | \
awk '{print $2" "$3 " " $1" "$4$5$6$7$8$9$10$11$12$13}' | sudo sudo tee httpx-raws.out; 
cat httpx-raws.out | awk '{print $3}' | sudo tee httpx.out; 


#---------------------------------------------------------------------------------------------------------------------------------#
# Check Webstack
printf '%b\n\n\n'; echo -e "$OKGREEN Step4 : Uncovers technologies from Subdomain list $RESET"
cat subdomain.out | dnsx -silent -cname -resp | sudo tee webstack/webstack-cname.out;
cat httpx.out | sudo /home/tool/httpx -td | sudo tee webstack-httpx.out;


#---------------------------------------------------------------------------------------------------------------------------------#
# Virtualhost Discovery from subdomain list
printf '%b\n\n\n'; echo -e "$OKGREEN Step5 : Virtualhost Discovery from Subdomain list $RESET"
cat httpx-raws.out | grep vhost | awk '{print $3}' | sudo tee virtualhost.out;


#---------------------------------------------------------------------------------------------------------------------------------#
# Collecting data (url,endpoint,js,etc) from active crawling 
printf '%b\n\n\n'; echo -e "$OKGREEN Step6 : Crawling URL Data $RESET"
cat subdomain.out | sudo /home/tool/katana -jc -kf all,robotstxt,sitemapxml -jsl | sudo tee ./raws/allurls;

# Collect Hidden Subdomain
cat raws/allurls | awk -F[/:] '{print $4}' | sort -u | sudo tee subdomain-hidden.out


#---------------------------------------------------------------------------------------------------------------------------------#
# Processing URL list to generate Interest data
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


# Path > Brute
  cat raws/allurls | grep -v = | sed -e 's/\/[^\/]*$//' | sort -u | unfurl format %s://%d%p/ | sudo tee ./interest/pathuri-temp
  sort -u httpx.out ./interest/pathuri-temp | sudo tee ./interest/pathuri; sudo rm ./interest/pathuri-temp;

# Passing parameters ---> ./interest/passingparams
  grep "=" ./raws/allurls | egrep -i "${passext1}${passext2}" | egrep -v "${extjunk1}" | sudo tee output1;
  for i in $(cat output1); do URL="${i}"; LIST=(${URL//[=&]/=FUZZ&}); echo ${LIST} | awk -F '=' -vOFS='=' '{$NF="FUZZ"}1;' | sudo tee -a output2; done; 
  sort -u output2 | sudo tee ./interest/passingparams; 

# Parameter list ---> ./interest/paramsuniq
  sudo grep "=" ./raws/allurls | egrep -iv "${junk1}${ext1}${ext2}|\.htm" | sudo tee output1; \
  for i in $(cat output1); do URL="${i}"; LIST=(${URL//[=&]/=FUZZ&}); echo ${LIST} | sudo awk -F '=' -vOFS='=' '{$NF="FUZZ"}1;' | sudo tee -a output2; done; 
  sort -u output2 | sudo tee output3; sudo sed '/?/!d' output3 | sudo tee output4; 
  sort -u output4 ./interest/passingparams | sudo tee -a ./interest/paramsuniq; 
  sudo rm output[0-9];

# Query Strings Parameter keys ---> ./interest/querystrings-keys
  cat ./raws/allurls | unfurl keypairs | sort -u | sudo tee ./interest/querystrings-keys;

# Param > Brute
  cat interest/paramsuniq | cut -d"?" -f1 | sort -u | sudo tee ./interest/paramsuri;
  sudo sed -i 's/$/?FUZZ/' ./interest/paramsuri

# Interest URI < ./raws/allurls
  egrep -v '${junkpath1}' ./raws/allurls | egrep "${path1}${path2}${path3}" | sort -u > ./interest/interesturi-allurls 

# Parse Interest URI, endpoint from [linfinder] < ./raws/data-gospider
  egrep "\[linkfinder\]" ./raws/data-gospider | awk '{print $4" "$6}' | \
  egrep -v "${junk1}${junk2}${junk3}${junk4}${junk5}${junk6}${junk7}${junk8}${junk9}" | sort -u | sudo tee ./interest/interesturi-js ;



#---------------------------------------------------------------------------------------------------------------------------------#
# Generate Wordlist
printf '%b\n\n\n'; echo -e "$OKGREEN Step11 : Generate Wordlist (Parameter & Path) $RESET"

# Parameter  
  cat ./raws/allurls | unfurl keys | sudo tee ./wordlist/parameter-temp
  cat ./wordlist/parameter-temp | egrep -ve "\%|\." -ve "[a-zA-Z]{20,30}" | tr -d ':' | sort -u > ./wordlist/parameter; rm ./wordlist/parameter-temp;

# Path
  fil1="wp-(content|includes|json)|"
  fil2="(docs|drive)\.google|\%22|amp|sha(256|384|512)"
  cat ./interest/pathuri | egrep -v "=|${fil1}${fil2}${ext1}${ext2}" | unfurl path | sed 's#/#\n#g' | sort -u | egrep -v "[a-zA-Z]{20,40}" | sudo tee ./wordlist/paths







