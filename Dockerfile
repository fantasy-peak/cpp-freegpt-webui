FROM ubuntu:23.04

#use --build-arg LIB_DIR=/usr/lib for arm64 cpus
ARG LIB_DIR=/local/lib
RUN mkdir -p /local/lib

ENV LD_LIBRARY_PATH=$LIB_DIR:$LD_LIBRARY_PATH
ENV LIBRARY_PATH=$LIB_DIR:$LIBRARY_PATH

RUN apt-get update -y
RUN apt-get install -y libcurl4-openssl-dev wget libnss3 nss-plugin-pem ca-certificates
# RUN strings /lib/$(arch)-linux-gnu/libstdc++.so.6 | grep GLIBCXX_3.4

RUN wget https://github.com/lwthiker/curl-impersonate/releases/download/v0.6.0-alpha.1/libcurl-impersonate-v0.6.0-alpha.1.$(arch)-linux-gnu.tar.gz
RUN mv libcurl-impersonate-v0.6.0-alpha.1.$(arch)-linux-gnu.tar.gz $LIB_DIR
RUN cd $LIB_DIR && tar -xvf libcurl-impersonate-v0.6.0-alpha.1.$(arch)-linux-gnu.tar.gz && rm -rf libcurl-impersonate-v0.6.0-alpha.1.$(arch)-linux-gnu.tar.gz

WORKDIR /app

ADD bin /app/bin
ADD cfg /app/cfg
ADD client /app/client

RUN ls /app/bin
RUN ls /app/cfg

WORKDIR /app/bin

ENTRYPOINT ["sh", "-c", "./cpp-freegpt-webui ../cfg/cpp-free-gpt.yml"]
