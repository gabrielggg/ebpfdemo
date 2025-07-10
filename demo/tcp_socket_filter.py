#!/usr/bin/python
#


from __future__ import print_function
from bcc import BPF
from sys import argv

import sys
import socket
import os

interface="eth0"

print ("binding socket to '%s'" % interface)

bpf_text="""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

#define IP_TCP  6
#define ETH_HLEN 14

int http_filter(struct __sk_buff *skb) {

        u8 *cursor = 0;

        struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
        //filter IP packets (ethernet type = 0x0800)
        if (!(ethernet->type == 0x0800)) {
                goto DROP;
        }

        struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
        //filter TCP packets (ip next protocol = 0x06)
        if (ip->nextp != IP_TCP) {
                goto DROP;
        }

        goto KEEP;

        //keep the packet and send it to userspace returning -1
        KEEP:
        return -1;

        //drop the packet returning 0
        DROP:
        return 0;

}
"""

bpf = BPF(text=bpf_text, debug = 0)

function_http_filter = bpf.load_func("http_filter", BPF.SOCKET_FILTER)

#create raw socket, bind it to interface
#attach bpf program to socket created
BPF.attach_raw_socket(function_http_filter, interface)

#get file descriptor of the socket previously created inside BPF.attach_raw_socket
socket_fd = function_http_filter.sock

#create python socket object, from the file descriptor
sock = socket.fromfd(socket_fd,socket.PF_PACKET,socket.SOCK_RAW,socket.IPPROTO_IP)
#set it as blocking socket
sock.setblocking(True)

while 1:
  #retrieve raw packet from socket
  packet_str = os.read(socket_fd,2048)

  #convert packet into bytearray
  packet_bytearray = bytearray(packet_str) 
  print(packet_bytearray)

  print("")
