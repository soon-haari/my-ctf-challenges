FROM python:3.11

RUN apt update
RUN apt-get install -y socat python3 python3-pip
RUN pip3 install pillow

COPY ./chall.py /
COPY ./maze.png /
COPY ./secret.py /

CMD socat TCP-LISTEN:8786,reuseaddr,fork EXEC:"python3 /chall.py"

EXPOSE 8786