#!bin/bash
chmod a+x ./whois
export PORT=${PORT:-5007}
export WHOIS_TIMEOUT_SECONDS=${WHOIS_TIMEOUT_SECONDS:-5}
#export ALL_PROXY=socks5://127.0.0.1:7890
nohup ./whois -r online  > log.txt 2>&1 &
