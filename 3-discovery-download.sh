####################################################################################################################################
export GOROOT=/usr/lib/go
export GOPATH=$HOME/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH

# Workdir : $1_sub/Sudomy-Output/$1;
cd /root/sudomy/$1_sub/Sudomy-Output/$1
mkdir ./juicyfiles/download ./juicyfiles/download/js ./juicyfiles/download/js2 \
./juicyfiles/download/other ./juicyfiles/download/node_module


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
	egrep "\.js" ./raws/data-gau | hakcheckurl -t 40 | grep "200" | awk '{print $2}' | sudo tee gau-js-temp; 
	egrep "\[javascript\]" ./raws/data-gospider | awk '{print $3}' | sudo tee gospider-js-temp;

	# Other juicy files :: json, txt, toml, xml, yaml, etc : 1) Fetch other juicy file + 2) Crawling other juicy files 
	otherext="\.json|\.txt|\.yaml|\.toml|\.xml|\.config|\.tar|\.gz|\.log"
	egrep "${otherext}" ./raws/data-gau | hakcheckurl -t 40 | grep "200" | awk '{print $2}' | sudo tee gau-other-temp; 
	egrep "\[url\]" ./raws/data-gospider | egrep "${otherext}" | awk '{print $5}' | sudo tee gospider-other-temp;

		sort -u gau-js-temp gospider-js-temp > ./juicy/allJSfiles-temp1;
		sort -u gau-other-temp gospider-other-temp > ./juicy/otherfiles;

	# Delete junk js -- awk -F / '{print $NF}'
	cat ./juicy/allJSfiles-temp1 | grep "\.js" | cut -d"?" -f1 | egrep -v "${filterpath}${filter1}${filter2}${filter3}${filter4}" | \
	sort -u | sudo tee ./juicy/jsfiles

rm gau-other-temp gospider-other-temp gospider-js-temp gau-js-temp;


printf '%b\n\n\n'; echo -e "$OKGREEN Step1 : Downloading juicy files $RESET"
# Step 1.1 - Colecting js file (1)
  # Downloading juicy files
	cat ./juicyfiles/jsfiles | parallel -j 5 wget --force-directories -c -P ./juicyfiles/download/js --no-check-certificate;
	cat ./juicyfiles/otherfiles | parallel -j 5 wget --force-directories -c -P ./juicyfiles/download/other --no-check-certificate;

# Step 1.2 - Colecting js file (2)
	gf urls ./juicyfiles/ | egrep -v "\.json" | egrep "\.js" | cut -d"?" -f1 | \
	egrep -v "${junk1}${junk2}${junk3}${junk4}${junk5}${junk6}${junk7}${junk8}${junk9}${filterpath}${filter1}${filter2}${filter3}${filter4}" | \
	sort -u | egrep "\.js$" | tee ./juicyfiles/jsfiles2; 

	# Downloading
	cat ./juicyfiles/jsfiles2 | parallel -j 5 wget --force-directories -c -P ./juicyfiles/download/js2 --no-check-certificate;

# Step 1.3 
	# Collecting js file from /node_module
	cat ./juicyfiles/allJSfiles-temp1 | grep "node_module" | tee ./juicyfiles/node_module;

	# Downloading
	cat ./juicyfiles/node_module | parallel -j 5 wget --force-directories -c -P ./juicyfiles/download/node_module --no-check-certificate;

rm ./juicyfiles/allJSfiles-temp1;


#---------------------------------------------------------------------------------------------------------------------------------#
# Minify, re-indent bookmarklet unpack, deobuscate JS files
printf '%b\n\n\n'; echo -e "$OKGREEN Step2 : Minifying JS files $RESET"
find ./juicyfiles/download/ -type f -name "*.js" -exec js-beautify -r {} \;


#---------------------------------------------------------------------------------------------------------------------------------#
printf '%b\n\n\n'; echo -e "$OKGREEN Step3 : Collecting parameter & path $RESET"

# Collecting potential parameter from variable JS Files
	unbuffer egrep -r "var [a-zA-Z0-9_]+" --color=yes ./juicyfiles/download/js/ ./juicyfiles/download/js2/ | \
	sed -e 's, 'var','"$url"?',g' -e 's/ //g' | tee ./interest/variablefromjs

# Collecting potential wordlist from variable JS Files
	grep -roh "\"\/[a-zA-Z0-9_?&=/\-\#]*\"" ./juicyfiles/download/js* | sed -e 's/^"//' -e 's/"$//' | sort -u > ./wordlist/js-paths


