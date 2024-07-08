#!/bin/bash


#运行server 0 - 3 
for i in {0..32}; do 
./bin/server $i > /opt/bft/waterbear/var/replica$i.out 2>&1 &
done

./bin/client 100 1 1 a
wait 

# pkill -f './bin/server'

