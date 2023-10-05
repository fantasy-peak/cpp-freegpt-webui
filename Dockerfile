FROM ubuntu:23.04 as builder

#use --build-arg LIB_DIR=/usr/lib for arm64 cpus
ARG LIB_DIR=/usr/local/lib64
RUN mkdir -p /usr/local/lib64

ENV LD_LIBRARY_PATH=$LIB_DIR:$LD_LIBRARY_PATH
ENV LIBRARY_PATH=$LIB_DIR:$LIBRARY_PATH

RUN apt-get update -y
RUN apt-get install -y libcurl4-openssl-dev wget libnss3 nss-plugin-pem ca-certificates curl
# RUN strings /lib/$(arch)-linux-gnu/libstdc++.so.6 | grep GLIBCXX_3.4

RUN wget https://github.com/lwthiker/curl-impersonate/releases/download/v0.5.4/libcurl-impersonate-v0.5.4.$(arch)-linux-gnu.tar.gz
RUN mv libcurl-impersonate-v0.5.4.$(arch)-linux-gnu.tar.gz $LIB_DIR
RUN cd $LIB_DIR && tar -xvf libcurl-impersonate-v0.5.4.$(arch)-linux-gnu.tar.gz && rm -rf libcurl-impersonate-v0.5.4.$(arch)-linux-gnu.tar.gz

FROM builder as chrome_builder
# install Chrome
# https://stackoverflow.com/questions/70955307/how-to-install-google-chrome-in-a-docker-container
RUN curl -LO  https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
RUN apt-get install -y ./google-chrome-stable_current_amd64.deb
RUN rm google-chrome-stable_current_amd64.deb
# Check chrome version
RUN echo "Chrome: " && google-chrome --version

FROM chrome_builder

WORKDIR /app

ADD bin /app/bin
ADD cfg /app/cfg
ADD client /app/client

RUN ls /app/bin
RUN ls /app/cfg

WORKDIR /app/bin

ENTRYPOINT ["sh", "-c", "./start.sh"]
