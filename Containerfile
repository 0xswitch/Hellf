FROM alpine:3.12.2

LABEL Hellf latest
ARG HELLF_VERSION=master
ENV HELLF_VERSION ${HELLF_VERSION}
VOLUME ["/mnt/tmp"]
RUN apk update && apk add python3 git
RUN python3 -m ensurepip
RUN pip3 install --no-cache --upgrade pip setuptools
RUN cd /mnt/tmp
RUN git clone -b "$HELLF_VERSION" https://github.com/0xswitch/Hellf
RUN pip3 install ./Hellf
RUN apk del git
CMD ["/bin/ash"]
