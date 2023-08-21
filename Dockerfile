FROM ubuntu:23.04

RUN apt-get update -y
RUN apt-get install -y valgrind
# RUN strings /lib/x86_64-linux-gnu/libstdc++.so.6 | grep GLIBCXX_3.4

WORKDIR /app

ADD bin /app/bin
ADD cfg /app/cfg
ADD client /app/client

RUN ls /app/bin
RUN ls /app/cfg

WORKDIR /app/bin

ENTRYPOINT ["sh", "-c", "valgrind --tool=memcheck --leak-check=full -s  --track-origins=yes ./cpp-freegpt-webui ../cfg/cpp-free-gpt.yml"]
