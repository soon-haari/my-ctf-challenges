FROM sagemath/sagemath:10.6  AS chroot

USER root

RUN apt-get update && apt-get install -y socat python3 python3-pip make && rm -rf /var/lib/apt/lists/*
RUN mkdir -m 777 /app

USER sage

COPY ./distfiles/chall.sage /app/

WORKDIR /app

RUN sage --preparse chall.sage

ENV FLAG "Alpaca{Sorry_for_BKZ_requiring_params_but_I_had_to_block_the_naive_solution_>:)}"
CMD ["/usr/bin/socat", "TCP-LISTEN:9999,reuseaddr,fork", "EXEC:\"/usr/bin/sage --nodotsage chall.sage.py\""]
