#!/bin/bash

# check the parameter
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <n> <start_port>"
    exit 1
fi

# number of nodes
n=$1

# starter port
start_port=$2

IMAGE_NAME="DR-Store"
IMAGE_TAG="1.1"

# docker stop $(docker ps -a | grep "$IMAGE_NAME:$IMAGE_TAG" | awk '{print $1}')
sleep 3

# docker run --rm -itd \
#       --name bandwidth --cap-add=NET_ADMIN --net=container:bft-experiment-5 \
#       $IMAGE_NAME:$IMAGE_TAG /bin/bash -c "tc qdisc add dev lo root tbf rate 50mbit burst 10mb latency 50ms minburst 1540" 
#   echo "run limit！"

 docker run --rm -itd \
       --name bandwidth --cap-add=NET_ADMIN --net=container:bft-experiment-5 \
       $IMAGE_NAME:$IMAGE_TAG /bin/bash -c "tc qdisc del dev lo root" 
   echo "enabled run limit！"


# creater and run n  replicas
for i in $(seq 0 $n); 
do
  cpu1=$((2*i))
  cpu2=$((2*i+1))
  echo "run $i docker..."
  docker run --cpus=2 --cpuset-cpus="$cpu1,$cpu2" --memory=2g --rm -itd \
      --name $IMAGE_NAME-0$i --net=container:bft-experiment-5 \
      -v /opt/bft/DR-Store/logs/:/home/fin/var \
      $IMAGE_NAME:$IMAGE_TAG /bin/bash -c "./bin/server $i > /home/DR-Store/var/replica$i.out 2>&1" 
  echo $IMAGE_NAME-$i
  echo " $i docker run success！"
done

sleep 3

# create and run client
echo "run client..."
docker run --cpus=2 --memory=2g --rm -itd \
    --name $IMAGE_NAME-0client --net=container:bft-experiment-5 \
    -v /opt/bft/DR-Store/logs/:/home/DR-Store/var \
    $IMAGE_NAME:$IMAGE_TAG /bin/bash -c "./bin/client 100 1 25000 a > /home/DR-Store/var/client.out 2>&1"
echo "client run success！"
#docker stop $(docker ps -a | grep DR-Store:1.1 | awk '{print $1}' )
#tc qdisc del dev eth0 root
#tc qdisc show dev eth0

sleep 3


