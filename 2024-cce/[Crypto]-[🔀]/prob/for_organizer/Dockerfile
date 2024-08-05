FROM ubuntu:latest

RUN apt update
RUN apt-get install -y socat python3 python3-pip

COPY ./src/chall.py /
COPY ./src/myAES.py /
COPY ./src/secret.py /

CMD socat TCP-LISTEN:3771,reuseaddr,fork EXEC:"python3 /chall.py"

EXPOSE 3771