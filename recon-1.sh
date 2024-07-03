
OKGREEN='\033[1;33m'; RESET='\e[0m';
export GOROOT=/usr/lib/go
export GOPATH=$HOME/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH

#---------------------------------------------------------------------------------------------------------------------------------#
# Enumerating subdomains + collecting urls (Tool : sudomy)
echo -e "$OKGREEN Subdomain Enumeration $RESET"
cd /home/Sudomy; ./sudomy -d $1 --no-probe -o $1; 
cd $1/Sudomy-Output/$1; mkdir raws webstack vuln vuln/fuzzing ;
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
cat subdomain.out | dnsx -silent -cname -resp | sudo tee webstack-cname.out;
cat httpx.out | sudo /home/tool/httpx -td | sudo tee webstack-httpx.out;
cat webstack-cname.out webstack-httpx.out | sudo tee webstack.out | sudo rm webstack-cname.out webstack-httpx.out;


#---------------------------------------------------------------------------------------------------------------------------------#
# Virtualhost Discovery from subdomain list
printf '%b\n\n\n'; echo -e "$OKGREEN Step5 : Virtualhost Discovery from Subdomain list $RESET"
cat httpx-raws.out | grep vhost | awk '{print $3}' | sudo tee virtualhost.out;


#---------------------------------------------------------------------------------------------------------------------------------#
# Collecting data (url,endpoint,js,etc) from active crawling 
printf '%b\n\n\n'; echo -e "$OKGREEN Step6 : Crawling URL Data $RESET"
cat subdomain.out | sudo /home/tool/katana -jc -kf all,robotstxt,sitemapxml -jsl | sudo tee ./raws/allurls-active;
cat httpx.out | /home/tool/gau --providers wayback,commoncrawl,otx,urlscan | sudo tee ./raws/allurls-passive;
sort -u raws/allurls-passive raws/allurls-active | sudo tee raws/allurls;


#---------------------------------------------------------------------------------------------------------------------------------#
# Collect Hidden Subdomain
cat raws/allurls | awk -F[/:] '{print $4}' | sort -u | sudo tee subdomain-hide-temp.out;
diff subdomain.out subdomain-hide-temp.out | sudo tee subdomain-hide.out; sudo rm subdomain-hide-temp.out;


#---------------------------------------------------------------------------------------------------------------------------------#
# Colecting Juicy file 
printf '%b\n\n\n'; echo -e "$OKGREEN Step7 : Collect interesting Path & Files $RESET"
cd /home/Sudomy/$1/Sudomy-Output/$1
filterpath="(\/cdn|wp-(content|admin|includes)\/|\?ver=|\/recaptcha|wwww\.google)|"
filter1="s3Capcha|wow\.min|jasny-bootstrap|jasny-bootstrap\.min|node_modules|";
filter2="jquery|ravenjs|static\.freshdev|"
filter3="wpgroho|polyfill\.min|bootstrap|";
filter4="myslider|modernizr|modernizr\.(min|custom)|hip";	

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
junk8="node_modules)|\_next|\%0A|";
junk9="zdassets\.com|datadoghq|googletagmanager\.com|unpkg\.com"

		# Collect List Files (js,txt,json)
		egrep "\.js|\.json|\.txt|\.yaml|\.toml|\.xml|\.config|\.tar|\.gz|\.log" ./raws/allurls | cut -d"?" -f1 | \
		egrep -v "${filterpath}${filter1}${filter2}${filter3}${filter4}" | sort -u | sudo tee ./raws/listfiles;

		# Discovery Interest Path
		egrep -v "${junkpath1}${junk1}${junk2}${junk3}${junk4}${junk5}${junk6}${junk7}${junk8}${junk9}" ./raws/allurls | \
		egrep "${path1}${path2}${path3}" | sudo tee raws/path-interest;

		# Collect Path --> Bruteforce
		cat raws/allurls | grep -v = | sed -e 's/\/[^\/]*$//' | egrep -v "${junk1}${junk2}${junk3}${junk4}${junk5}${junk6}${junk7}${junk8}${junk9}" | \
		unfurl format %s://%d%p/ | sort -u | sudo /home/tool/httpx | sudo tee raws/path-uri; 


