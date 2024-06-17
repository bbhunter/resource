export GOROOT=/usr/lib/go
export GOPATH=$HOME/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH

#---------------------------------------------------------------------------------------------------------------------------------#
# S3 Bucket Discovery
cd /root/sudomy/$1_sub/Sudomy-Output/$1

# From $1_sub/Sudomy-Output/$1
	gf s3-buckets | sort -u | tee ./automationtesting/s3bucket-all;

# Bruteforce 
echo ".s3.amazonaws.com" >> ./wordlist/domain-temp; 

	# Wordlist /resource/wordlist/s3cbucket
	s3enum --wordlist /root/resource/wordlist/s3bucket/prefixlist.txt --suffixlist /root/resource/wordlist/s3bucket/suffixlist.txt \
	--threads 15 $1 | tee ./wordlist/s3bucketnames-temp1;	
	comb ./wordlist/s3bucketnames-temp1 ./wordlist/domain-temp >> ./wordlist/s3bucketnames-temp1;
	
	# Wordlist from subdomains name
	cat subdomain.out | cut -d "." -f1 | tee prefix-s3-temp;
	s3enum --wordlist prefix-s3-temp; --suffixlist /root/resource/wordlist/s3bucket/suffixlist.txt \
	--threads 15 $1 | tee ./wordlist/s3bucketnames-temp2;	
	comb ./wordlist/s3bucketnames-temp2 ./wordlist/domain-temp >> ./wordlist/s3bucketnames-temp2;
	
		sort -u ./wordlist/s3bucketnames-temp1 ./wordlist/s3bucketnames-temp2 > ./wordlist/s3bucketnames-temp
		cat ./wordlist/s3bucketnames-temp | egrep -v "(-|_)\." | tee ./wordlist/s3bucketnames;
		rm ./wordlist/s3bucketnames-temp[1-2] ./wordlist/domain-temp

		cat ./wordlist/s3bucketnames | httpx -status-code -threads 40 -timeout 5 | egrep '200|403' | awk '{print $1}' | \
		sed 's/https\?:\/\///' | tee ./automationtesting/s3bucket-brute;

# Copying result
rm -rf /var/www/html/automate/$1 /var/www/html/automate/$1.zip
cp -r /root/sudomy/$1_sub/Sudomy-Output/$1 /var/www/html/automate/$1
zip -r /var/www/html/automate/$1.zip /root/sudomy/$1_sub/Sudomy-Output/$1
curl -X POST -H 'Content-type: application/json' --data '{"text":"Automate S3 Bucket Discovery Done :)"}' \
https://hooks.slack.com/services/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


#---------------------------------------------------------------------------------------------------------------------------------#
# Discovery Sensitive Data Exposure : Scanning juice files
printf '%b\n\n\n'; echo -e "$OKGREEN Step1 - Discovery Sensitive Data Exposure : Scanning juice files $RESET"
unbuffer gf sensitive-generic1 ./juicyfiles/download/ | tee ./automationtesting/sensitivedata-generic1;
unbuffer gf sensitive-generic2 ./juicyfiles/download/ | tee ./automationtesting/sensitivedata-generic2;
unbuffer gf sensitive ./juicyfiles/download/ | tee ./automationtesting/sensitivedata;


#---------------------------------------------------------------------------------------------------------------------------------#
# Subdomain Takeover: Subdomain > CNAME resolv > NXDOMAIN | Pattern matching
printf '%b\n\n\n'; echo -e "$OKGREEN Step3 - Subdomain Takeover $RESET"
dnsprobe -l subdomain.out -r CNAME -o $1_dnsprobe_cnames -silent; 
cat $1_dnsprobe_cnames | awk '{print $1}' >> $1_cnames; rm $1_dnsprobe_cnames;

parallel -j 20 host {1} {2} :::: $1_cnames ::: 8.8.8.8 1.1.1.1 8.8.4.4 | tee takeover-dnslookup;
cat takeover-dnslookup | grep "NXDOMAIN" | awk '{print $2" "$7}' | tee ./automationtesting/takeover-nxdomain; 
rm takeover-dnslookup;

subjack -w $1_cnames -timeout 30 -ssl -o subjack-results -c /root/resource/src/subjack-fingerprints.json -v 3; 
cat subjack-results | awk '$0 !~ /Not Vulnerable/' | tee ./automationtesting/takeover-subjack; rm subjack-results;


