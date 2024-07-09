
ARG APP_PORT=11000

FROM golang:1.15.14

ENV BASE_DIR="/home/waterbear"
# set workdir
WORKDIR $BASE_DIR

# RUN apt-get -y update \
#     && apt-get -y install iproute2

RUN apt-get -y install iproute2


COPY . $BASE_DIR/

RUN export GOPATH=$PWD&&export GOBIN=$PWD/bin&&export GO111MODULE=off
ENV GOPATH $BASE_DIR
ENV GOBIN $BASE_DIR/bin
RUN make build


ENV PORT=$APP_PORT