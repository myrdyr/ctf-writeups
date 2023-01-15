#!/usr/bin/env python3

import socket
import struct
import select

TCP_IP = "127.0.0.1"
TCP_PORT = 10015

sockets = []

def main():
    for i in range(11):
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect((TCP_IP, TCP_PORT))
        sockets.append(conn)

    print(sockets[0].recv(4096).decode("utf-8"))
    print(sockets[0].recv(4096).decode("utf-8"))

    total = 0
    for i in range(1, 11):
        num = struct.unpack("!L", sockets[i].recv(4))[0]
        print(num)
        total += num
    print(total)


    total = struct.pack("!L", total)
    print([total])
    sockets[0].sendall(total)

    print(sockets[0].recv(4096).decode("utf-8"))

    while True:
        reads = select.select(sockets[1:], list(), list())[0]
        if not reads: break
        for read in reads:
            print(read.recv(1024).decode(),end="")


if __name__ == "__main__":
    main()
