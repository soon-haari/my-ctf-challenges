FROM sagemath/sagemath:10.6  AS chroot

USER root

RUN apt-get update && apt-get install -y socat python3 python3-pip make && rm -rf /var/lib/apt/lists/*
RUN mkdir -m 777 /app

USER sage

COPY ./distfiles/chall.sage /app/

WORKDIR /app

RUN sage --preparse chall.sage

ENV FLAG "Alpaca{Oh_I_forgor_GF_allows_these_weird_values_:'(}"
CMD ["/usr/bin/socat", "TCP-LISTEN:9999,reuseaddr,fork", "EXEC:\"/usr/bin/sage --nodotsage chall.sage.py\""]
