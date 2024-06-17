####################################################################################################################################
automate-brute (){
# Workdir : $1_sub/Sudomy-Output/$1;
cd /root/sudomy/$1_sub/Sudomy-Output/$1
mkdir brute;

# Dir/path
	# Vhost internal path
	printf '%b\n\n\n'; echo -e "$OKGREEN Step1.1 - Bruteforce Vhost Internal Path $RESET"
	for i in $(cat virtualhost.out); do  ffuf -u $i/FUZZ -w /root/resource/wordlist/dir/internalpath.txt \
	-H "User-Agent: Mozilla/5.0 Windows NT 10.0 Win64 AppleWebKit/537.36 Chrome/69.0.3497.100" -H "X-Forwarded-For: 127.0.0.1" \
	-H "Host: localhost" -c -fs 0 -t 10 -mc 200 -recursion ; done | tee ahaaaa; 
	cat ahaaaa | egrep -v "Method|Header|Follow|Calib|Timeout|Thread|Matc|Filt|v1|_|^$" | tee ./brute/internalpath; rm ahaaaa;	

	# Sort wordlist
	printf '%b\n\n\n'; echo -e "$OKGREEN Step1.2 - Bruteforce Sort Wordlist $RESET"
	for i in $(cat ./interest/pathuri); do  ffuf -u $i/FUZZ -w /root/resource/wordlist/dir/short-wordlist.txt \
	-H "User-Agent: Mozilla/5.0 Windows NT 10.0 Win64 AppleWebKit/537.36 Chrome/69.0.3497.100" -H "X-Forwarded-For: 127.0.0.1" \
	-c -fs 0 -t 10 -mc 200 -recursion ; done | tee ahaaaa; 
	cat ahaaaa | egrep -v "Method|Header|Follow|Calib|Timeout|Thread|Matc|Filt|v1|_|^$" | tee ./brute/sortwordlist; rm ahaaaa;

	# Spring boot
	printf '%b\n\n\n'; echo -e "$OKGREEN Step1.3 - Bruteforce Springboot Wordlist $RESET"
	for i in $(cat ./interest/pathuri); do  ffuf -u $i/FUZZ -w /root/resource/wordlist/dir/spring-boot.txt \
	-H "User-Agent: Mozilla/5.0 Windows NT 10.0 Win64 AppleWebKit/537.36 Chrome/69.0.3497.100" -H "X-Forwarded-For: 127.0.0.1" \
	-c -fs 0 -t 10 -mc 200 -recursion ; done | tee bbbbb; 
	cat bbbbb | egrep -v "Method|Header|Follow|Calib|Timeout|Thread|Matc|Filt|v1|_|^$" | tee ./brute/springboot; rm bbbbb;

	# Big Wordlist
	printf '%b\n\n\n'; echo -e "$OKGREEN Step1.4 - Bruteforce Big Wordlist $RESET"
	for i in $(cat httpx.out); do  ffuf -u $i/FUZZ -w /root/resource/wordlist/dir/big-wordlist.txt \
	-H "User-Agent: Mozilla/5.0 Windows NT 10.0 Win64 AppleWebKit/537.36 Chrome/69.0.3497.100" -H "X-Forwarded-For: 127.0.0.1" \
	-c -fs 0 -t 10 -mc 200 -recursion ; done | tee xxxxx; 
	cat xxxxx | egrep -v "Method|Header|Follow|Calib|Timeout|Thread|Matc|Filt|v1|_|^$" | tee ./brute/bigwordlist; rm xxxxx;


# Parameter
printf '%b\n\n\n'; echo -e "$OKGREEN Step2 - Parameter Discovery $RESET"
python3 /root/tools/arjun/arjun.py --urls ./interest/paramsuri -f ./wordlist/parameter -t 15 -o ./brute/parameter1
python3 /root/tools/arjun/arjun.py --urls ./interest/paramsuri -f /root/resource/wordlist/params.txt -t 15 -o ./brute/parameter2


#---------------------------------------------------------------------------------------------------------------------------------#
# Copying result
rm -rf /var/www/html/automate/$1 /var/www/html/automate/$1.zip
cp -r /root/sudomy/$1_sub/Sudomy-Output/$1 /var/www/html/automate/$1
zip -r /var/www/html/automate/$1.zip /root/sudomy/$1_sub/Sudomy-Output/$1
curl -X POST -H 'Content-type: application/json' --data '{"text":"Automate Bruteforce Done :)"}' \
https://hooks.slack.com/services/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
}
