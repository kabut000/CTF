FROM ubuntu:18.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update 
RUN apt install -y socat gdb

COPY ./libc.so.6 /home/
COPY ./bird /home/

ENV LD_PRELOAD /home/libc.so.6 

WORKDIR /home/
