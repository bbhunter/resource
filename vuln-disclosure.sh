#---------------------------------------------------------------------------------------------------------------------------------#
# CVE Advisories based on Webstack
/home/tool/nuclei -l subdomain.out -as | sudo tee vuln/nuclei-cvewebstack-subdomain.out;
/home/tool/nuclei -l ipresolv.out -as | sudo tee vuln/nuclei-cvewebstack-ipresolv.out;

#---------------------------------------------------------------------------------------------------------------------------------#
# Subdomain Takeover: Subdomain > CNAME resolv > NXDOMAIN | Pattern matching
printf '%b\n\n\n'; echo -e "$OKGREEN Step2 - Subdomain Takeover $RESET"
/home/tool/nuclei -l subdomain.out -t /home/tool/pattern/takeover/dns/* -t /home/tool/pattern/takeover/http/*;


#---------------------------------------------------------------------------------------------------------------------------------#
# Discovery Sensitive Data Exposure : 2 Tools
printf '%b\n\n\n'; echo -e "$OKGREEN Step1 - Discovery Sensitive Data Exposure : Scanning juice files $RESET"
cat raws/listfiles | sudo /home/tool/httpx -mc 200 | while read url; do python3 /home/tool/secretfinder/SecretFinder.py \
 -i $url -o cli; done | sudo tee vuln/dataexposure

sudo /home/tool/trufflehog filesystem ./raws/download;

