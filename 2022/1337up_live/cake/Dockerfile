FROM ubuntu:18.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update 
RUN apt install -y socat gdb

COPY ./libc-2.27.so /home/
COPY ./cake /home/

ENV LD_PRELOAD /home/libc-2.27.so 

WORKDIR /home/
