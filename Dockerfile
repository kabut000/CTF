FROM ubuntu:18.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y socat gdb git
RUN git clone https://github.com/longld/peda.git ~/peda
RUN echo "source ~/peda/peda.py" >> ~/.gdbinit

COPY ./test/a.out /home/pwn/

# ENV LD_PRELOAD /home/pwn/libc-2.27.so

WORKDIR /home/pwn

# CMD socat tcp-l:7777,reuseaddr,fork system:./chall
# CMD socat tcp-l:7777,reuseaddr,fork 'system:gdbserver localhost\:8888 ./one'

