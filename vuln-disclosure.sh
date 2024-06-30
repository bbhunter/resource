#---------------------------------------------------------------------------------------------------------------------------------#
# CVE Advisories based on Webstack
/home/tool/nuclei -l subdomain.out -as | sudo tee vuln/nuclei-cvewebstack.out;


#---------------------------------------------------------------------------------------------------------------------------------#
# Subdomain Takeover: Subdomain > CNAME resolv > NXDOMAIN | Pattern matching
printf '%b\n\n\n'; echo -e "$OKGREEN Step2 - Subdomain Takeover $RESET"
/home/tool/nuclei -l subdomain.out -t /home/tool/pattern/takeover/dns/* -t /home/tool/pattern/takeover/http/*;


#---------------------------------------------------------------------------------------------------------------------------------#
# Discovery Sensitive Data Exposure : Scanning juice files --Online
printf '%b\n\n\n'; echo -e "$OKGREEN Step1 - Discovery Sensitive Data Exposure : Scanning juice files $RESET"
cat juicy/listfiles | sudo /home/tool/httpx -mc 200 | while read url; do python3 /home/tool/secretfinder/SecretFinder.py \
 -i $url -o cli; done | sudo tee vuln/dataexposure

# Discovery Sensitive Data Exposure : Scanning juice files --Local
sudo /home/tool/trufflehog filesystem juicy/;


#---------------------------------------------------------------------------------------------------------------------------------#
# Discovery Interest Path
egrep -v "${junkpath1}${junk1}${junk2}${junk3}${junk4}${junk5}${junk6}${junk7}${junk8}${junk9}" ./raws/allurls | \
egrep "${path1}${path2}${path3}" | sudo tee vuln/interestpath;




#---------------------------------------------------------------------------------------------------------------------------------#
# S3 Bucket Discovery
cd /root/sudomy/$1_sub/Sudomy-Output/$1

# From $1_sub/Sudomy-Output/$1
	gf s3-buckets | sort -u | tee ./automationtesting/s3bucket-all;

# Bruteforce 
echo ".s3.amazonaws.com" >> ./interest/wordlist/domain-temp; 

	# Wordlist /resource/interest/wordlist/s3cbucket
	s3enum --wordlist /root/resource/interest/wordlist/s3bucket/prefixlist.txt --suffixlist /root/resource/interest/wordlist/s3bucket/suffixlist.txt \
	--threads 15 $1 | tee ./interest/wordlist/s3bucketnames-temp1;	
	comb ./interest/wordlist/s3bucketnames-temp1 ./interest/wordlist/domain-temp >> ./interest/wordlist/s3bucketnames-temp1;
	
	# Wordlist from subdomains name
	cat subdomain.out | cut -d "." -f1 | tee prefix-s3-temp;
	s3enum --wordlist prefix-s3-temp; --suffixlist /root/resource/interest/wordlist/s3bucket/suffixlist.txt \
	--threads 15 $1 | tee ./interest/wordlist/s3bucketnames-temp2;	
	comb ./interest/wordlist/s3bucketnames-temp2 ./interest/wordlist/domain-temp >> ./interest/wordlist/s3bucketnames-temp2;
	
		sort -u ./interest/wordlist/s3bucketnames-temp1 ./interest/wordlist/s3bucketnames-temp2 > ./interest/wordlist/s3bucketnames-temp
		cat ./interest/wordlist/s3bucketnames-temp | egrep -v "(-|_)\." | tee ./interest/wordlist/s3bucketnames;
		rm ./interest/wordlist/s3bucketnames-temp[1-2] ./interest/wordlist/domain-temp

		cat ./interest/wordlist/s3bucketnames | httpx -status-code -threads 40 -timeout 5 | egrep '200|403' | awk '{print $1}' | \
		sed 's/https\?:\/\///' | tee ./automationtesting/s3bucket-brute;

