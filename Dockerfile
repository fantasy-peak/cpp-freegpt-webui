FROM ubuntu:23.04

ENV LD_LIBRARY_PATH=/usr/lib64:$LD_LIBRARY_PATH
ENV LIBRARY_PATH=/usr/lib64:$LIBRARY_PATH

RUN apt-get update -y
RUN apt-get install -y libcurl4-openssl-dev wget libnss3 nss-plugin-pem ca-certificates
# RUN strings /lib/x86_64-linux-gnu/libstdc++.so.6 | grep GLIBCXX_3.4

RUN wget https://github.com/lwthiker/curl-impersonate/releases/download/v0.5.4/libcurl-impersonate-v0.5.4.x86_64-linux-gnu.tar.gz
RUN mv libcurl-impersonate-v0.5.4.x86_64-linux-gnu.tar.gz /usr/lib64
RUN cd /usr/lib64 && tar -xvf libcurl-impersonate-v0.5.4.x86_64-linux-gnu.tar.gz && rm -rf libcurl-impersonate-v0.5.4.x86_64-linux-gnu.tar.gz

WORKDIR /app

ADD bin /app/bin
ADD cfg /app/cfg
ADD client /app/client

RUN ls /app/bin
RUN ls /app/cfg

WORKDIR /app/bin

ENTRYPOINT ["sh", "-c", "./cpp-freegpt-webui ../cfg/cpp-free-gpt.yml"]
