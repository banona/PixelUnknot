#!/bin/bash

if [ -z "$3" ]; then
  usage "$0 domain board threadid" 
  exit
fi

#  which chan and board
DOMAIN=$1
BOARD=$2
THREAD=$3

URL=https://boards.$DOMAIN/$BOARD/thread/$THREAD
IMGS=is2.$DOMAIN

wget -P $THREAD -nd -np -r -l 1 -e robots=off -H -D $IMGS -A jpg,jpeg $URL
for F in $THREAD/*.jp*g; do python detect.py $F; done
