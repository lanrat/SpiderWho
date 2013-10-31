#!/usr/bin/env bash

URL="http://www.sysnet.ucsd.edu/cgi-bin/whoami.sh"

PORT=30000
FAIL=0


for i in $(seq 1 32);
do
    echo "trying ccied$i"
    #scp discover.sh ccied$i:.
    ssh -oPasswordAuthentication=no -oConnectTimeout=01 ccied$i "./discover.sh"
done

