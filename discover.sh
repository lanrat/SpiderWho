#!/usr/bin/env bash

URL="http://www.sysnet.ucsd.edu/cgi-bin/whoami.sh"

PORT=30000
FAIL=0


while true; do
    PROXY="127.0.0.1:$PORT"
    IP="`http_proxy=$PROXY wget -q -T 2 -O - $URL | sed -ne '/^[0-9.]*$/p'`"
    if [ -n "$IP" ]; then
        echo "$PORT $IP"
        FAIL=0
    else
        FAIL=$((FAIL+1))
        if [ $FAIL = 5 ]; then
            exit
        fi
    fi
    PORT=$((PORT+1))
done

exit
