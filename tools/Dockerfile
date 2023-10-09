FROM ubuntu:23.04

RUN rm /bin/sh && ln -s /bin/bash /bin/sh
RUN apt-get update -y
RUN apt-get install -y python3/lunar python3.11-venv dbus-x11/lunar curl nodejs/lunar tree

# install Chrome
# https://stackoverflow.com/questions/70955307/how-to-install-google-chrome-in-a-docker-container
RUN curl -LO  https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
RUN apt-get install -y ./google-chrome-stable_current_amd64.deb
RUN rm google-chrome-stable_current_amd64.deb
# Check chrome version
RUN echo "Chrome: " && google-chrome --version

WORKDIR /app

COPY ./npm /app/npm
ADD requirements.txt /app
ADD zeus.py /app

RUN python3 -m venv venv \
    && source venv/bin/activate \
    && pip install -r requirements.txt

ENTRYPOINT ["sh", "-c", "source venv/bin/activate && python3 zeus.py"]
