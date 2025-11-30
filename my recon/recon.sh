#!/bin/bash

# Check for input argument
if [ -z "$1" ]; then
    echo "Usage: $0 <domain or file with domains>"
    exit 1
fi

# Ask about waybackurls at the start
echo -n "[?] Do you want to run waybackurls? (y/n): "
read run_wayback

# If input is wildcard.txt, run addscope
if [ "$1" == "wildcard.txt" ]; then
    echo "[*] Detected wildcard.txt - running addscope"
    addscope wildcard.txt
fi

# Create output directories
mkdir -p recon_results/subfinder
mkdir -p recon_results/assetfinder
mkdir -p recon_results/subdomains
mkdir -p recon_results/fff_output/requests
mkdir -p recon_results/fff_output/requests/headers
mkdir -p recon_results/fff_output/requests/body
mkdir -p recon_results/fff_output/titles
mkdir -p recon_results/cors
mkdir -p recon_results/urls
mkdir -p recon_results/urls/waybackurls
mkdir -p recon_results/juicy


# Final unique subdomains file
unique_output="recon_results/subdomains/all_unique_subdomains.txt"
touch "$unique_output"

# Check if input is a file or single domain
if [ -f "$1" ]; then
    domains=$(cat "$1")
else
    domains=$1
fi

# Process each domain
for domain in $domains; do
    clean_domain=$(echo "$domain" | sed 's/*\.//g') # remove wildcard if exists

    echo "[*] Running recon for: $clean_domain"

    # Subfinder
    subfinder -d "$clean_domain" -silent -o "recon_results/subfinder/$clean_domain.txt"
    cat "recon_results/subfinder/$clean_domain.txt" | anew "$unique_output"

    # Assetfinder
    assetfinder --subs-only "$clean_domain" > "recon_results/assetfinder/$clean_domain.txt"
    cat "recon_results/assetfinder/$clean_domain.txt" | anew "$unique_output"

    echo "[-] Finished $clean_domain"
done

# Check if file is provided
if [ -z "$1" ]; then
  echo "Usage: $0 domains.txt"
  exit 1
fi

# Loop through each domain for waybackurls 


if [ "$run_wayback" = "y" ] || [ "$run_wayback" = "Y" ]; then
  while read -r domain; do
    output_file="recon_results/urls/waybackurls/$domain.txt"
    touch "$output_file"
    echo "$domain" | tee "$output_file"
    echo "[*] Fetching waybackurls for: $domain"
    cat "$output_file" | waybackurls | anew "$output_file"
  done < "$1"
else
  echo "[*] Skipping waybackurls..."
fi

# In-scope filtering
echo "[*] Running inscope on final subdomains"
cat "$unique_output" | inscope | tee recon_results/subdomains/subdomains.txt

# Probing live hosts
echo "[*] Running httprobe"
cat recon_results/subdomains/subdomains.txt | httprobe -c 80 -prefer-https | anew httprobe.txt

# Saving headers with fff
echo "[*] Running fff on probed hosts"
cat httprobe.txt | fff -d 1 -S -o recon_results/fff_output/roots
cat recon_results/fff_output/roots/*/*.headers | tee recon_results/fff_output/requests/headers/all-headers.txt 
cat recon_results/fff_output/roots/*/*.body | tee recon_results/fff_output/requests/body/all-bodys.txt 

# Checking for CORS 
echo "[*] Checking for CORS vulnerable hosts"
cat httprobe.txt | fff -d 1 -H "origin: https://evil.com" -S -o recon_results/cors/requests
grep -rH "Access-Control-Allow-Origin: https://evil.com/" recon_results/cors/requests/*/ | cut -d/ -f4 | sort -u | httpx -sc -o recon_results/cors/vulnerable.txt 

# Detecting server info
echo "[*] Gathering server info"
grep -rH "Server:" recon_results/fff_output/roots/*/ | while IFS= read -r line; do
    # Get server name
    server=$(echo "$line" | sed -E 's/.*Server:[[:space:]]*//')

    # Get first-level dir (4th field in path)
    dirname=$(echo "$line" | cut -d/ -f4)

    # Make server directory (relative path)
    mkdir -p "recon_results/fff_output/servers/$server"

    # Append domain into file
    echo "$dirname" >> "recon_results/fff_output/servers/$server/$dirname"
done


# Body urls
echo "[*] Collecting urls form body of domains"
cd recon_results/fff_output/requests/body
gf urls | inscope | anew ../../../urls/urls-from-body.txt 
gf urls | anew all-urls-from-body.txt 
cd ../../../../

#Extraction of title form roots
find recon_results/fff_output/roots/*/*.body -type f | while read f; do
    # Extract the <title> content
    title=$(grep -i "<title" "$f" | sed -E 's/.*<title[^>]*>(.*?)<\/title>.*/\1/I')
    
    # Sanitize title to use as a safe filename
    safe_title=$(echo "$title" | tr -cd '[:alnum:]_.-')
    
    # Extract domain from the path
    domain=$(echo "$f" | cut -d/ -f4)
    
    # Save the domain to the corresponding title file
    echo "$domain" >> "recon_results/fff_output/titles/$safe_title.txt"
done

#Getting js files 
echo "[*] Searching js files"
grep -rEo 'https?://[^"]+\.js' . | cut -d: -f2- | inscope | anew recon_results/urls/js.txt 
cat recon_results/urls/js.txt | fff -d 1 -S -o recon_results/fff_output/js 

# Searching Juicy content 
echo "[*] Searching for aws-keys"
gf aws-keys | anew recon_results/juicy/aws-keys.txt

echo "[*] Searching for s3-buckets"
gf s3-buckets | anew recon_results/juicy/s3-buckets.txt

echo "[*] Searching for base64"
gf base64 | anew recon_results/juicy/base64.txt

echo "[*] Searching for upload-fields"
gf upload-fields| anew recon_results/juicy/upload-fields.txt

echo "[*] Searching for secretes" 
gf sec | anew recon_results/juicy/secretes.txt 

echo "[*] Searching for api-keys"
gf api-keys | anew recon_results/juicy/api-keys.txt

echo "[*] Searching for debug-pages"
gf debug-pages | anew recon_results/juicy/debug-pages.txt 

echo "[*] Searching for JWT Tokens"
gf jwt | anew recon_results/juicy/jwt.txt 

echo "[*] Searching for LFI"
cd recon_results/urls                                           # we are in /recon_results/urls dir
gf lfi |  cut -d: -f3-  | anew ../juicy/lfi.txt 

echo "[*] Searching for RCE" 
gf rce |  cut -d: -f3-  | anew ../juicy/rce.txt

echo "[*] Searching for open-redirect"
gf redirect |  cut -d: -f3-  | anew ../juicy/open-redirect.txt 

echo "[*] Searching for SQLi"
gf sqli | cut -d: -f3- | anew ../juicy/sqli.txt

echo "[*] Searching for interestingEXT"
gf interestingEXT | cut -d: -f3- |  awk '/\.pdf$/ {pdf[++i]=$0; next} 1; END {for (j=1;j<=i;j++) print pdf[j]}' | anew ../juicy/interestingEXT.txt 
cd ../..                                                       # back to home dir

echo "[+] Recon complete."
echo "[+] Unique subdomains saved to: $unique_output"
echo "[+] In-scope subdomains saved to: recon_results/subdomains/subdomains.txt"
echo "[+] Live subdomains saved to: httprobe.txt"
echo "[+] Root-level responses saved in: recon_results/fff_output/roots"
echo "[+] CORS vulnrable hosts saved in: recon_results/cors/vulnerable.txt"
echo "[+] Servers info saved in: recon_results/fff_output/servers"
echo "[+] Waybackurls saved in: recon_results/urls/waybackurls"
echo "[+] Extracted Titles saved in: recon_results/fff_output/titles"
echo "[+] fff on js file saved in: recon_results/fff_output/js"
echo "[+] Juicy content saved in : recon_results/juicy"

