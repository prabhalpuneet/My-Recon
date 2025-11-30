apt install subfinder -y 
apt install assetfinder -y 
apt install -y golang-go
apt install paramspider -y
apt install arjun -y

wget https://github.com/tomnomnom/waybackurls/releases/download/v0.0.2/waybackurls-linux-386-0.0.2.tgz
tar -xzf waybackurls-linux-386-0.0.2.tgz
cp waybackurls /bin/
mv waybackurls /usr/bin/
rm waybackurls-linux-386-0.0.2.tgz
cp .gf /root/
cp .gf /home/kali/
mv addscope.sh /usr/local/bin/addscope
rm /usr/bin/httpx
rm /bin/httpx
rm /usr/local/bin/httpx
go install github.com/tomnomnom/hacks/inscope@latest
go install github.com/tomnomnom/httprobe@latest
go install github.com/tomnomnom/anew@latest
go install github.com/tomnomnom/gf@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/tomnomnom/fff@latest
go install github.com/bp0lr/gauplus@latest
go install -v github.com/PentestPad/subzy@latestt

cp /root/go/bin/* /usr/bin/
cp /root/go/bin/* /bin 
cp recon.sh /usr/local/bin/recon 
cp recon.sh /bin/recon
cp recon.sh /usr/bin/recon 

