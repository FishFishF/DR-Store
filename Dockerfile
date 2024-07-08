# 定义构建时的变量
ARG APP_PORT=11000

# 使用 Golang 的基础镜像
FROM golang:1.15.14

ENV BASE_DIR="/home/waterbear"
# 设置工作目录
WORKDIR $BASE_DIR

# RUN apt-get -y update \
#     && apt-get -y install iproute2

RUN apt-get -y install iproute2

# 将项目文件复制到容器中
COPY . $BASE_DIR/

RUN export GOPATH=$PWD&&export GOBIN=$PWD/bin&&export GO111MODULE=off
ENV GOPATH $BASE_DIR
ENV GOBIN $BASE_DIR/bin
RUN make build

# 设置环境变量，使用构建时的变量作为默认值
ENV PORT=$APP_PORT