#!/bin/bash


IMAGE_NAME="waterbear-jzh"
IMAGE_TAG="1.1"

#create docker

docker stop $(docker ps -a | grep "$IMAGE_NAME:$IMAGE_TAG" | awk '{print $1}')
# docker rm $(docker ps -a | grep "$IMAGE_NAME:$IMAGE_TAG" | awk '{print $1}')
docker rmi "$IMAGE_NAME:$IMAGE_TAG"
docker build -t $IMAGE_NAME:$IMAGE_TAG  .