FROM ubuntu:22.04@sha256:965fbcae990b0467ed5657caceaec165018ef44a4d2d46c7cdea80a9dff0d1ea

RUN apt update
RUN apt-get install -y socat python3 python3-pip

ENV TERM=linux

RUN pip install py-ecc

COPY ./distfiles/chall.py /

ENV FLAG "Alpaca{Not-a-0day-https://github.com/Consensys/gnark-crypto/blob/master/ecc/bn254/g2.go#L208-L226}"
CMD socat TCP-LISTEN:9997,reuseaddr,fork EXEC:"python3 /chall.py"

EXPOSE 9997