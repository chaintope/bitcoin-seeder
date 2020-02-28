#!/bin/bash
source /etc/profile.d/aws-apitools-common.sh

ZONEID=ZKAPA71BL90VS
NSHOST=ns.tapyrus.dev.chaintope.com
HOST=seed.tapyrus.dev.chaintope.com
EMAIL=nakajo@chaintope.com
NETWORK="-i1939510133"
INIT_SEED="-s1939510133:seed.tapyrus.dev.chaintope.com"

TTL=60
NEWIP=`/usr/bin/curl -s "http://169.254.169.254/2008-02-01/meta-data/public-ipv4"`

# update route53
/usr/bin/route53 change_record ${ZONEID} ${NSHOST}. A ${NEWIP} ${TTL}

# screen up
screen -S seeder -X quit
screen -dmS seeder
sleep 3s

# launch seeder
screen -S seeder -X -p 0 exec sudo tapyrusseed ${NETWORK} ${INIT_SEED} -h ${HOST} -n ${NSHOST} -m ${EMAIL} --testnet
