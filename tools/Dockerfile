FROM rockylinux:9.2

RUN dnf upgrade --refresh -y

RUN dnf install https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm https://dl.fedoraproject.org/pub/epel/epel-next-release-latest-9.noarch.rpm -y
RUN dnf install chromium -y

WORKDIR /app

COPY ./npm /app/npm
ADD requirements.txt /app
ADD zeus.py /app

RUN python3 -m venv venv \
    && source venv/bin/activate \
    && pip install -r requirements.txt

ENTRYPOINT ["sh", "-c", "source venv/bin/activate && python3 zeus.py"]
