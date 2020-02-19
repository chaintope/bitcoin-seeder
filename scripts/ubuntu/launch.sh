#!/bin/bash
APPPATH=/var/config/aws/

ZONEID=ZKAPA71BL90VS
NSHOST=ns.tapyrus.dev.chaintope.com
HOST=seed.tapyrus.dev.chaintope.com
EMAIL=nakajo@chaintope.com
NETWORK="-i1939510133"
INIT_SEED="-s1939510133:seed.tapyrus.dev.chaintope.com"

TTL=60
NEWIP=`/usr/bin/curl -s "http://169.254.169.254/2008-02-01/meta-data/public-ipv4"`

# update route53
sudo sed -e "s/{%IP%}/${NEWIP}/g;s/{%HOST%}/${NSHOST}/g" ./dyndns.json > ${APPPATH}${NSHOST}.json
sudo aws route53 change-resource-record-sets --hosted-zone-id ${ZONEID} --change-batch file://${APPPATH}${NSHOST}.json

# screen up
screen -S seeder -X quit
screen -dmS seeder
sleep 3s

# launch seeder
screen -S seeder -X -p 0 exec sudo tapyrusseed ${NETWORK} ${INIT_SEED} -h ${HOST} -n ${NSHOST} -m ${EMAIL} --testnet
