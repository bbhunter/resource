####################################################################################################################################
export GOROOT=/usr/lib/go
export GOPATH=$HOME/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH

# Port scan subdomains
printf '%b\n\n\n'; echo -e "$OKGREEN Step1.1 : Subdomain Port Scan Common Port $RESET"	
cat raws/subdomain-resolved | awk '{print $2}' | sort -u | httpx -vhost -threads 30 -silent -ports 4443,8000-8099,8880,8888,8443,9200 | \
sudo tee httpx-9999.out; rm temp temp2 resolv[0-9];

# Port scan ip 
printf '%b\n\n\n'; echo -e "$OKGREEN Step1.2 : IP lis Port Scan Full Port $RESET"
naabu -t 10 -hL cf-ipresolv.out -ports full -exclude-ports 1-200 -retries 3 | sudo tee openport.out;

