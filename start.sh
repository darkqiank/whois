#!bin/bash
chmod a+x ./whois
export PORT=5007
#export ALL_PROXY=socks5://127.0.0.1:7890
nohup ./whois -r online  > log.txt 2>&1 &